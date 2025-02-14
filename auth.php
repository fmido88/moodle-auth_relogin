<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Authentication class for relogin is defined here.
 *
 * @package     auth_relogin
 * @copyright   2023 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();
global $CFG;
require_once($CFG->libdir.'/authlib.php');

// For further information about authentication plugins please read
// https://docs.moodle.org/dev/Authentication_plugins.
//
// The base class auth_plugin_base is located at /lib/authlib.php.
// Override functions as needed.

/**
 * Authentication class for relogin.
 */
class auth_plugin_relogin extends auth_plugin_base {

    /**
     * Set the properties of the instance.
     */
    public function __construct() {
        $this->authtype = 'relogin';
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username.
     * @param string $password The password.
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {

        return false;
    }

    /**
     * Returns true if this authentication plugin can change the user's password.
     *
     * @return bool
     */
    public function can_change_password() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can edit the users'profile.
     *
     * @return bool
     */
    public function can_edit_profile() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal() {
        return false;
    }

    /**
     * Indicates if password hashes should be stored in local moodle database.
     *
     * @return bool True means password hash stored in user table, false means flag 'not_cached' stored there instead.
     */
    public function prevent_local_passwords() {
        return false;
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from get_userinfo() method.
     *
     * @return bool True means automatically copy data from ext to user table.
     */
    public function is_synchronised_with_external() {
        return false;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool.
     */
    public function can_reset_password() {
        return false;
    }

    /**
     * Returns true if plugin allows signup and user creation.
     *
     * @return bool
     */
    public function can_signup() {
        return false;
    }

    /**
     * Returns true if plugin allows confirming of new users.
     *
     * @return bool
     */
    public function can_confirm() {
        return false;
    }

    /**
     * Returns whether or not this authentication plugin can be manually set
     * for users, for example, when bulk uploading users.
     *
     * This should be overridden by authentication plugins where setting the
     * authentication method manually is allowed.
     *
     * @return bool
     */
    public function can_be_manually_set() {
        return false;
    }

    /**
     * Hook for overriding behavior of login page.
     * This method is called from login/index.php page for all enabled auth plugins.
     *
     */
    public function loginpage_hook() {
        global $CFG;
        if (!empty(get_config('auth_relogin', 'loginpage'))) {
            $done = $this->pre_loginpage_hook();
            if ($done) {
                require_once($CFG->dirroot.'/login/lib.php');
                $redirect = core_login_get_return_url();
                redirect(new \moodle_url($redirect));
            }
        }
    }

    /**
     * Hook for overriding behavior before going to the login page.
     *
     * This method is called from require_login from potentially any page for
     * all enabled auth plugins and gives each plugin a chance to redirect
     * directly to an external login page, or to instantly login a user where
     * possible.
     *
     * If an auth plugin implements this hook, it must not rely on ONLY this
     * hook in order to work, as there are many ways a user can browse directly
     * to the standard login page. As a general rule in this case you should
     * also implement the loginpage_hook as well.
     *
     */
    public function pre_loginpage_hook() {
        if (isloggedin() && !isguestuser()) {
            return false;
        }

        if (AJAX_SCRIPT || CLI_SCRIPT) {
            return false;
        }

        global $DB, $CFG, $SESSION;
        // Try to automatic login the user by two different ways
        // once by check http_cookies and another by ip address.
        list($found, $sid) = $this->get_user_by_cookies();
        // We did our best.
        if (!self::is_valid_user($found)) {
            return false;
        }

        // Prepare the events reader.
        // In this part we check for logged out event with the same session id.
        // This is a double check to not relogin the user that is already logged out by himself.
        // Todo delete this part after making sure that the cookies get deleted after logging out.
        $logmanager = get_log_manager();
        $readers    = $logmanager->get_readers('core\log\sql_reader');
        $reader     = array_pop($readers);

        if ($reader !== null) {
            $params = [
                'userid'   => $found->id,
                'objectid' => $found->id,
                'action'   => 'loggedout',
                'target'   => 'user',
                'time'     => time() - 30 * DAYSECS, // Cookies age.
            ];
            $where = 'userid = :userid AND objectid = :objectid AND action = :action AND timecreated >= :time';
            $loggedout = $reader->get_events_select($where, $params, 'timecreated DESC', 0, 0);
            // Check if the user already logged out in this period of time.
            foreach ($loggedout as $l) {
                if ($l->other['sessionid'] == $sid) {
                    debugging('Cookies aren\'t deleted properly after logging out.', DEBUG_DEVELOPER);
                    return false;
                }
            }
        }

        // Use manual if auth not set.
        $userauth = empty($found->auth) ? 'manual' : $found->auth;
        if ($userauth == 'nologin') {
            return false;
        }

        if (!empty($SESSION->has_timed_out)) {
            unset($SESSION->has_timed_out);
        }

        // Login the user.
        $user = complete_user_login($found);

        if (!empty($user->id) && !isguestuser($user)) {
            \core\session\manager::apply_concurrent_login_limit($user->id, session_id());
            if (optional_param('sesskey', false, PARAM_BOOL)) {
                // This means that the current page contains a submitted form.
                // To avoid resubmission or invalid sesskey exception, Redirect.
                redirect(new moodle_url('/'));
            }
            return true;
        }

        return false;
    }

    /**
     * Check if the user exists in moodle and not guest, suspended or deleted.
     * @param object|bool $user
     * @return bool
     */
    public static function is_valid_user($user) {
        if (
            empty($user)
            || empty($user->id)
            || !core_user::is_real_user($user->id, true)
            || isguestuser($user)
            || !empty($user->deleted)
            || !empty($user->suspended)
            ) {
            return false;
        }
        return true;
    }

    /**
     * Check if the user has a saved relogin cookies.
     * returns the user object and the session id.
     * @return array|null
     */
    public static function get_user_by_cookies() {
        global $DB, $SITE, $CFG;
        $matches = [];
        // Check the plugin cookies.
        $cookiesname = (!empty($SITE->shortname)) ? 'ReLoginMoodle'.$SITE->shortname : 'ReLoginMoodle';
        if (isset($_COOKIE[$cookiesname])) {
            $matches[] = $_COOKIE[$cookiesname];
        }

        // Check moodle cookies.
        if (!isset($CFG->sessioncookie)) {
            $sessionname = 'MoodleSession';
        } else {
            $sessionname = 'MoodleSession'.$CFG->sessioncookie;
        }

        if (isset($_COOKIE[$sessionname])) {
            $matches[] = $_COOKIE[$sessionname];
        }

        if (!empty($matches)) {
            foreach ($matches as $sid) {
                $record = $DB->get_record('sessions', ['sid' => $sid]);
                if (!$record) {
                    // The session expired.
                    continue;
                }

                $user = get_complete_user_data('id', $record->userid);
                if (!self::is_valid_user($user)) {
                    continue;
                }

                // Double check if the session is not timed out.
                $exist = \core\session\manager::session_exists($sid);
                if (!$exist) {
                    // Session expired.
                    continue;
                }
                return [$user, $sid];
            }
        }
        return null;
    }

    /**
     * Post logout hook.
     *
     * This method is used after moodle logout by auth classes to execute server logout.
     *
     * @param stdClass $user clone of USER object before the user session was terminated
     */
    public function postlogout_hook($user) {
        global $CFG, $DB, $SITE;
        // When the user logout normally, making sure this plugin didn't log him again.
        // Also it enhance security.
        // Unset this plugin cookies.
        $cookiesname = (!empty($SITE->shortname)) ? 'ReLoginMoodle'.$SITE->shortname : 'ReLoginMoodle';
        $options = [
            'expires'  => time() - DAYSECS * 30,
            'path'     => $CFG->sessioncookiepath,
            'domain'   => $CFG->sessioncookiedomain,
            'secure'   => is_moodle_cookie_secure(),
            'httponly' => $CFG->cookiehttponly,
        ];
        if (\core_useragent::is_chrome() && \core_useragent::check_chrome_version('78') && is_moodle_cookie_secure()) {
            // If $samesite is empty, we don't want there to be any SameSite attribute.
            $options['samesite'] = 'None';
        }
        $cookiesname = str_replace(["=", ",", ";", " ", "\t", "\r", "\n", "\013", "\014"], '', $cookiesname);
        setcookie($cookiesname, '', $options);
        unset($_COOKIE[$cookiesname]);
    }
}
