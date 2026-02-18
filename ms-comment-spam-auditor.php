<?php
/**
 * Plugin Name: MS Comment Spam Auditor
 * Description: Identifies sites in a Multisite network with likely comment spam issues. Low-memory scanning with SQL-only heuristics, batching, daily cron, manual rescan, and WP-CLI. Robust against sites with corrupted wp_user_roles.
 * Version: 1.3.1
 * Author: Leonie Winson
 * Network: true
 * Requires at least: 5.8
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) exit;

final class MS_Comment_Spam_Auditor {
	const OPT_SETTINGS     = 'ms_csa_settings';        // network option
	const OPT_LAST_RESULTS = 'ms_csa_last_results';    // network option (cached results)
	const CRON_HOOK        = 'ms_csa_daily_scan';
	const NONCE_ACTION     = 'ms_csa_action';

	private static $instance = null;

	public static function instance() {
		return self::$instance ?? ( self::$instance = new self() );
	}

	private function __construct() {
		if ( ! is_multisite() ) {
			add_action( 'admin_notices', function () {
				echo '<div class="notice notice-error"><p><strong>MS Comment Spam Auditor</strong> requires Multisite. Please deactivate.</p></div>';
			} );
			return;
		}

		add_action( 'network_admin_menu', [ $this, 'register_network_menu' ] );
		add_action( 'admin_init', [ $this, 'register_settings' ] );

		// Cron
		add_action( self::CRON_HOOK, [ $this, 'run_scan_and_store' ] );

		// Activation / Deactivation
		register_activation_hook( __FILE__, [ __CLASS__, 'activate' ] );
		register_deactivation_hook( __FILE__, [ __CLASS__, 'deactivate' ] );

		// WP-CLI
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			WP_CLI::add_command( 'ms-spam-audit', [ $this, 'cli_command' ] );
		}
	}

	public static function activate() {
		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + 300, 'daily', self::CRON_HOOK ); // start in ~5min, then daily
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public function default_settings(): array {
		return [
			// Scanner behavior
			'lookback_days'        => 14,     // window to analyze
			'spam_threshold'       => 25,     // spam count to flag
			'pending_threshold'    => 20,     // pending count to flag
			'spam_ratio_threshold' => 0.40,   // spam / (approved + spam)
			'link_threshold'       => 2,      // number of links in comment content considered suspicious

			// Performance
			'light_mode'           => 1,      // 1 = SQL-only heuristics (low memory)
			'batch_size'           => 50,     // sites per batch when scanning a large network
			'heuristics_cutoff'    => 5000,   // if pending+spam candidates >= this, skip keyword/link checks

			// Heuristics
			'keyword_list'         => 'viagra, casino, porn, loan, bitcoin, telegram, whatsapp, seo, escort, forex, hack, payday, win money, replica, xxx',
		];
	}

	public function get_settings(): array {
		$saved = get_site_option( self::OPT_SETTINGS, [] );
		return wp_parse_args( $saved, $this->default_settings() );
	}

	/**
	 * Settings are registered (harmless), but we self-handle saving in the UI.
	 */
	public function register_settings() {
		register_setting( 'ms_csa_settings_group', self::OPT_SETTINGS, [
			'type'              => 'array',
			'sanitize_callback' => [ $this, 'sanitize_settings' ],
			'show_in_rest'      => false,
		] );

		add_settings_section( 'ms_csa_main', 'Scan Settings', function () {
			echo '<p>Configure thresholds and performance options. <em>Light mode</em> uses SQL-only checks (low memory usage).</p>';
		}, 'ms_csa_settings' );
	}

	public function sanitize_settings( $input ) {
		$defaults = $this->default_settings();
		$out = [];
		$out['lookback_days']         = max( 1, intval( $input['lookback_days'] ?? $defaults['lookback_days'] ) );
		$out['spam_threshold']        = max( 1, intval( $input['spam_threshold'] ?? $defaults['spam_threshold'] ) );
		$out['pending_threshold']     = max( 0, intval( $input['pending_threshold'] ?? $defaults['pending_threshold'] ) );
		$out['spam_ratio_threshold']  = min( 1, max( 0, floatval( $input['spam_ratio_threshold'] ?? $defaults['spam_ratio_threshold'] ) ) );
		$out['link_threshold']        = max( 1, intval( $input['link_threshold'] ?? $defaults['link_threshold'] ) );
		$out['batch_size']            = max( 5, intval( $input['batch_size'] ?? $defaults['batch_size'] ) );
		$out['heuristics_cutoff']     = max( 0, intval( $input['heuristics_cutoff'] ?? $defaults['heuristics_cutoff'] ) );
		$out['light_mode']            = ! empty( $input['light_mode'] ) ? 1 : 0;

		$kw = sanitize_text_field( $input['keyword_list'] ?? $defaults['keyword_list'] );
		$parts = array_filter( array_map( function( $k ){ return trim( mb_strtolower( $k ) ); }, explode( ',', $kw ) ) );
		$out['keyword_list'] = implode( ', ', array_unique( $parts ) );

		return $out;
	}

	public function register_network_menu() {
		// Report page under Network Settings
		add_submenu_page(
			'settings.php',
			'Spam Audit',
			'Spam Audit',
			'manage_network',
			'ms-csa',
			[ $this, 'render_network_page' ]
		);

		// Settings page (self-saves; no options.php redirect)
		add_submenu_page(
			'settings.php',
			'Spam Audit Settings',
			'Spam Audit Settings',
			'manage_network',
			'ms_csa_settings',
			[ $this, 'render_settings_page' ]
		);
	}

	public function render_settings_page() {
		if ( ! current_user_can( 'manage_network' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'ms-csa' ) );
		}

		$opt_name  = self::OPT_SETTINGS;
		$settings  = $this->get_settings();
		$updated   = false;
		$error_msg = '';

		// Self-handled POST (avoids "page not found" in Network Admin)
		if ( isset( $_POST['ms_csa_save'] ) && check_admin_referer( self::NONCE_ACTION ) ) {
			try {
				$raw   = isset( $_POST[ $opt_name ] ) ? (array) $_POST[ $opt_name ] : [];
				$clean = $this->sanitize_settings( $raw );
				update_site_option( $opt_name, $clean );
				$settings = $clean;
				$updated = true;
			} catch ( \Throwable $e ) {
				$error_msg = $e->getMessage();
			}
		}

		echo '<div class="wrap"><h1>Spam Audit Settings</h1>';
		if ( $updated ) echo '<div class="notice notice-success"><p>Settings saved.</p></div>';
		if ( $error_msg ) echo '<div class="notice notice-error"><p>'.esc_html($error_msg).'</p></div>';

		echo '<form method="post">';
		wp_nonce_field( self::NONCE_ACTION );

		$fields = [
			'lookback_days'        => [ 'Lookback window (days)', 'number', 'min="1" max="60"' ],
			'spam_threshold'       => [ 'Flag if spam ≥', 'number', 'min="1" step="1"' ],
			'pending_threshold'    => [ 'Flag if pending ≥', 'number', 'min="0" step="1"' ],
			'spam_ratio_threshold' => [ 'Flag if spam ratio ≥', 'number', 'min="0" max="1" step="0.01"' ],
			'link_threshold'       => [ 'Suspicious if links in comment ≥', 'number', 'min="1" step="1"' ],
			'keyword_list'         => [ 'Suspicious keywords (comma-separated)', 'text', 'size="80"' ],
			'light_mode'           => [ 'Light mode (SQL-only, low memory)', 'checkbox', '' ],
			'batch_size'           => [ 'Sites per batch', 'number', 'min="5" step="5"' ],
			'heuristics_cutoff'    => [ 'Skip keyword/link checks if candidates ≥', 'number', 'min="0" step="500"' ],
		];

		echo '<table class="form-table">';
		foreach ( $fields as $key => $meta ) {
			$label = esc_html( $meta[0] );
			$type  = $meta[1];
			$attr  = $meta[2] ?? '';
			$val   = $settings[ $key ] ?? '';
			echo '<tr><th><label for="'.esc_attr($key).'">'.$label.'</label></th><td>';
			if ( $type === 'checkbox' ) {
				printf(
					'<label><input id="%1$s" name="%2$s[%1$s]" type="checkbox" value="1" %3$s /> Enable</label>',
					esc_attr( $key ),
					esc_attr( $opt_name ),
					checked( ! empty( $val ), true, false )
				);
			} else {
				printf(
					'<input id="%1$s" name="%2$s[%1$s]" type="%3$s" value="%4$s" %5$s />',
					esc_attr( $key ),
					esc_attr( $opt_name ),
					esc_attr( $type ),
					esc_attr( $val ),
					$attr
				);
			}
			echo '</td></tr>';
		}
		echo '</table>';

		echo '<p class="submit"><button type="submit" name="ms_csa_save" class="button button-primary">Save Changes</button></p>';
		echo '</form></div>';
	}

	public function render_network_page() {
		if ( ! current_user_can( 'manage_network' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'ms-csa' ) );
		}

		// Actions: manual rescan
		if ( isset( $_POST['ms_csa_rescan'] ) && check_admin_referer( self::NONCE_ACTION ) ) {
			$this->run_scan_and_store();
			echo '<div class="notice notice-success"><p>Scan complete.</p></div>';
		}

		$settings = $this->get_settings();
		$results  = get_site_option( self::OPT_LAST_RESULTS, [
			'scanned_at' => 0,
			'rows'       => [],
		] );
		$scanned_at = $results['scanned_at'] ? date_i18n( get_option('date_format').' '.get_option('time_format'), $results['scanned_at'] ) : 'Never';

		echo '<div class="wrap">';
		echo '<h1>Multisite Comment Spam Audit</h1>';

		echo '<p><em>Last scan:</em> ' . esc_html( $scanned_at ) . '</p>';
		echo '<form method="post" style="margin-bottom:1em;">';
		wp_nonce_field( self::NONCE_ACTION );
		echo '<input type="submit" class="button button-primary" name="ms_csa_rescan" value="Run Scan Now" />';
		echo ' <a href="' . esc_url( network_admin_url( 'settings.php?page=ms_csa_settings' ) ) . '" class="button">Settings</a>';
		echo '</form>';

		// Table
		echo '<table class="widefat striped"><thead><tr>';
		$cols = [ 'Site', 'Spam (window)', 'Pending', 'Spam ratio', 'Keyword hits', 'Link-heavy', 'Verdict', 'Error' ];
		foreach ( $cols as $c ) echo '<th>'.esc_html( $c ).'</th>';
		echo '</tr></thead><tbody>';

		if ( empty( $results['rows'] ) ) {
			echo '<tr><td colspan="8">No data. Run a scan.</td></tr>';
		} else {
			foreach ( $results['rows'] as $row ) {
				// Only build admin link for sites we successfully scanned (no error)
				if ( empty( $row['error'] ) ) {
					$site_link = sprintf(
						'<a href="%s">%s</a>',
						esc_url( get_admin_url( $row['blog_id'], 'edit-comments.php' ) ),
						esc_html( $row['site_name'] )
					);
				} else {
					$site_link = esc_html( $row['site_name'] );
				}

				$verdict = $row['flagged'] ? '<span style="color:#b32d2e;font-weight:600;">⚠ Needs attention</span>' : '<span style="color:#2271b1;">OK</span>';
				$error   = empty( $row['error'] ) ? '—' : esc_html( $row['error'] );

				printf(
					'<tr>
						<td>%s<br><small>%s</small></td>
						<td>%d</td>
						<td>%d</td>
						<td>%s</td>
						<td>%d</td>
						<td>%d</td>
						<td>%s</td>
						<td>%s</td>
					</tr>',
					$site_link,
					esc_html( $row['home'] ),
					intval( $row['spam_count'] ),
					intval( $row['pending_count'] ),
					esc_html( number_format_i18n( $row['spam_ratio'] * 100, 1 ) . '%' ),
					intval( $row['keyword_hits'] ),
					intval( $row['link_heavy_hits'] ),
					$verdict,
					$error
				);
			}
		}

		echo '</tbody></table>';

		echo '<p style="margin-top:1em;">Window: last '.intval($settings['lookback_days']).' days. Thresholds: spam ≥ '.intval($settings['spam_threshold']).', pending ≥ '.intval($settings['pending_threshold']).', ratio ≥ '.floatval($settings['spam_ratio_threshold']).'.</p>';
		echo '<p><em>Performance:</em> Light mode is '.( $settings['light_mode'] ? 'enabled' : 'disabled' ).'; Batch size: '.intval($settings['batch_size']).' sites; Heuristics cutoff: '.intval($settings['heuristics_cutoff']).'.</p>';
		echo '</div>';
	}

	/**
	 * Cron + manual entrypoint: compute results & store once for quick display.
	 */
	public function run_scan_and_store() {
		$results = [
			'scanned_at' => time(),
			'rows'       => $this->scan_network(),
		];
		update_site_option( self::OPT_LAST_RESULTS, $results );
		return $results;
	}

	/**
	 * Read wp_user_roles for a given blog WITHOUT switching sites.
	 * Returns array on success, or null if missing/invalid.
	 */
	private function get_roles_option_without_switch( int $blog_id ) {
		global $wpdb;
		$table = $wpdb->get_blog_prefix( $blog_id ) . 'options';
		$sql = "SELECT option_value FROM {$table} WHERE option_name = 'wp_user_roles' LIMIT 1";
		$raw = $wpdb->get_var( $sql );
		if ( null === $raw ) return null;
		$val = function_exists( 'maybe_unserialize' ) ? maybe_unserialize( $raw ) : @unserialize( $raw );
		return is_array( $val ) ? $val : null;
	}

	/**
	 * The main scanner. Returns array of per-site rows.
	 * Low-memory: scans in batches; uses SQL-only heuristics (no comment body loops).
	 * Hardened: checks roles without switching; skips corrupted sites.
	 */
	private function scan_network(): array {
		global $wpdb;

		$settings   = $this->get_settings();
		$since_ts   = time() - ( DAY_IN_SECONDS * $settings['lookback_days'] );
		$since_sql  = gmdate( 'Y-m-d H:i:s', $since_ts );
		$keywords   = array_filter( array_map( 'trim', explode( ',', mb_strtolower( $settings['keyword_list'] ) ) ) );
		$link_thresh= (int) $settings['link_threshold'];
		$batch_size = (int) $settings['batch_size'];

		$total = (int) get_sites( [ 'count' => true, 'deleted' => 0, 'archived' => 0, 'spam' => 0 ] );
		$pages = (int) ceil( max(1, $total) / max(1, $batch_size) );
		$rows  = [];

		for ( $p = 0; $p < $pages; $p++ ) {
			$sites = get_sites( [
				'number'   => $batch_size,
				'offset'   => $p * $batch_size,
				'deleted'  => 0,
				'archived' => 0,
				'spam'     => 0,
			] );

			foreach ( $sites as $site ) {
				$blog_id = (int) $site->blog_id;

				// Guard: check roles option WITHOUT switching (bad roles cause fatals in switch_to_blog()).
				$roles_option = $this->get_roles_option_without_switch( $blog_id );
				if ( ! is_array( $roles_option ) ) {
					$scheme     = function_exists('is_ssl') && is_ssl() ? 'https://' : 'http://';
					$domain     = isset( $site->domain ) ? $site->domain : 'example.com';
					$path       = isset( $site->path ) ? $site->path : '/';
					$home_guess = $scheme . $domain . $path;

					$rows[] = [
						'blog_id'         => $blog_id,
						'site_name'       => 'Site #'.$blog_id,
						'home'            => $home_guess,
						'spam_count'      => 0,
						'pending_count'   => 0,
						'spam_ratio'      => 0,
						'keyword_hits'    => 0,
						'link_heavy_hits' => 0,
						'flagged'         => false,
						'error'           => 'Skipped: invalid wp_user_roles (not an array)',
					];
					continue;
				}

				$switched = false;
				try {
					switch_to_blog( $blog_id );
					$switched = true;

					$home      = home_url();
					$site_name = get_bloginfo( 'name' );

					// Counts (fast SQL with status/date)
					$spam_count = (int) $wpdb->get_var( $wpdb->prepare(
						"SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = 'spam' AND comment_date_gmt >= %s",
						$since_sql
					) );

					$pending_count = (int) $wpdb->get_var( $wpdb->prepare(
						"SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = '0' AND comment_date_gmt >= %s",
						$since_sql
					) );

					$approved_count = (int) $wpdb->get_var( $wpdb->prepare(
						"SELECT COUNT(*) FROM {$wpdb->comments} WHERE comment_approved = '1' AND comment_date_gmt >= %s",
						$since_sql
					) );

					$denominator = max( 1, $spam_count + $approved_count );
					$spam_ratio  = $spam_count / $denominator;

					// Candidate size for heuristics (pending + spam in window)
					$candidate_count = (int) $wpdb->get_var( $wpdb->prepare(
						"SELECT COUNT(*) FROM {$wpdb->comments}
						 WHERE (comment_approved = 'spam' OR comment_approved = '0')
						   AND comment_date_gmt >= %s",
						$since_sql
					) );

					$do_heuristics = $settings['light_mode'] && ( (int) $settings['heuristics_cutoff'] === 0 || $candidate_count < (int) $settings['heuristics_cutoff'] );

					// --- SQL-only heuristics (low-memory) ---
					$keyword_hits = 0;
					$link_heavy   = 0;

					if ( $do_heuristics ) {
						$kw = array_filter( $keywords );
						if ( ! empty( $kw ) ) {
							// Build a REGEXP alternation: (viagra|casino|bitcoin)
							$escaped = array_map( function( $s ) {
								// Escape regex metachars for MySQL REGEXP
								return preg_replace( '/[\\\\.^$|()\\[\\]{}*+?]/', '\\\\$0', $s );
							}, $kw );
							$pattern = '(' . implode( '|', $escaped ) . ')';

							$keyword_hits = (int) $wpdb->get_var( $wpdb->prepare(
								"SELECT COUNT(*) FROM {$wpdb->comments}
								 WHERE (comment_approved = 'spam' OR comment_approved = '0')
								   AND comment_date_gmt >= %s
								   AND LOWER(comment_content) REGEXP %s",
								$since_sql,
								$pattern
							) );
						}

						// Approximate "link-heavy" by counting http occurrences via LIKE
						if ( $link_thresh >= 2 ) {
							$link_heavy = (int) $wpdb->get_var( $wpdb->prepare(
								"SELECT COUNT(*) FROM {$wpdb->comments}
								 WHERE (comment_approved = 'spam' OR comment_approved = '0')
								   AND comment_date_gmt >= %s
								   AND LOWER(comment_content) LIKE '%%http%%http%%'",
								$since_sql
							) );
						} else {
							$link_heavy = (int) $wpdb->get_var( $wpdb->prepare(
								"SELECT COUNT(*) FROM {$wpdb->comments}
								 WHERE (comment_approved = 'spam' OR comment_approved = '0')
								   AND comment_date_gmt >= %s
								   AND LOWER(comment_content) LIKE '%%http%%'",
								$since_sql
							) );
						}
					}

					$flagged = (
						$spam_count >= (int) $settings['spam_threshold']
						|| $pending_count >= (int) $settings['pending_threshold']
						|| $spam_ratio >= (float) $settings['spam_ratio_threshold']
						|| $keyword_hits >= 10
						|| $link_heavy >= 10
					);

					$rows[] = [
						'blog_id'         => $blog_id,
						'site_name'       => $site_name,
						'home'            => $home,
						'spam_count'      => $spam_count,
						'pending_count'   => $pending_count,
						'spam_ratio'      => $spam_ratio,
						'keyword_hits'    => $keyword_hits,
						'link_heavy_hits' => $link_heavy,
						'flagged'         => $flagged,
						'error'           => '',
					];
				} catch ( \Throwable $e ) {
					// If switching or querying failed, do NOT call helpers that might switch again.
					$scheme     = function_exists('is_ssl') && is_ssl() ? 'https://' : 'http://';
					$domain     = isset( $site->domain ) ? $site->domain : 'example.com';
					$path       = isset( $site->path ) ? $site->path : '/';
					$home_guess = $scheme . $domain . $path;

					$rows[] = [
						'blog_id'         => $blog_id,
						'site_name'       => 'Site #'.$blog_id,
						'home'            => $home_guess,
						'spam_count'      => 0,
						'pending_count'   => 0,
						'spam_ratio'      => 0,
						'keyword_hits'    => 0,
						'link_heavy_hits' => 0,
						'flagged'         => false,
						'error'           => 'Skipped: ' . $e->getMessage(),
					];
				} finally {
					if ( $switched ) {
						restore_current_blog();
					}
				}
			}

			// Free memory between batches
			if ( function_exists( 'gc_collect_cycles' ) ) gc_collect_cycles();
			wp_cache_flush();
		}

		// Sort: flagged first, then by spam_count desc
		usort( $rows, function( $a, $b ) {
			if ( $a['flagged'] !== $b['flagged'] ) return $a['flagged'] ? -1 : 1;
			return $b['spam_count'] <=> $a['spam_count'];
		} );

		return $rows;
	}

	/**
	 * WP-CLI: ms-spam-audit [--format=json]
	 */
	public function cli_command( $args, $assoc_args ) {
		$results = $this->run_scan_and_store();
		if ( isset( $assoc_args['format'] ) && 'json' === $assoc_args['format'] ) {
			WP_CLI::print_value( $results );
			return;
		}

		WP_CLI\Utils\format_items( 'table', array_map( function( $r ){
			return [
				'blog_id'      => $r['blog_id'],
				'site_name'    => $r['site_name'],
				'home'         => $r['home'],
				'spam'         => $r['spam_count'],
				'pending'      => $r['pending_count'],
				'spam_ratio'   => round( $r['spam_ratio'] * 100, 1 ) . '%',
				'kw_hits'      => $r['keyword_hits'],
				'link_heavy'   => $r['link_heavy_hits'],
				'flagged'      => $r['flagged'] ? 'yes' : 'no',
				'error'        => $r['error'],
			];
		}, $results['rows'] ), [ 'blog_id','site_name','home','spam','pending','spam_ratio','kw_hits','link_heavy','flagged','error' ] );

		WP_CLI::success( 'Scan complete.' );
	}
}

MS_Comment_Spam_Auditor::instance();
