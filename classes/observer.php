<?php
// This file is part of Moodle - http://moodle.org/
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
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Observers
 *
 * @package    auth_relogin
 * @copyright  2023 Mo Farouk <phun.for.physics@gmail.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace auth_relogin;
use auth_plugin_relogin;

/**
 * Observer class.
 *
 *
 * @package    auth_relogin
 * @copyright  2023 Mo Farouk <phun.for.physics@gmail.com>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class observer {

    /**
     * This is a callback function after a user is logged in successfully to make sure that
     * even if the login mechanism not calling user_authenticated_hook like oauth2
     * and the session is set to create cookies.
     *
     * @param \core\event\user_loggedin $event
     * @return void
     */
    public static function save_cookies(\core\event\user_loggedin $event) {
        global $CFG, $DB, $SITE;
        require_once($CFG->dirroot . '/auth/relogin/auth.php');
        $userid = $event->userid;

        if (!is_enabled_auth('relogin')) {
            return;
        }

        $user = \core_user::get_user($userid);
        if (!auth_plugin_relogin::is_valid_user($user)) {
            return;
        }

        if (!empty(session_id())) {
            $sid = session_id();
        } else {
            $sessions = $DB->get_records('sessions', ['userid' => $user->id], 'timemodified DESC', 'sid', 0, 1);
            if (!empty($sessions)) {
                $first = reset($sessions);
                $sid = $first->sid;
            } else {
                return;
            }
        }

        $options = [
            'expires'  => time() + DAYSECS * 30,
            'path'     => $CFG->sessioncookiepath,
            'domain'   => $CFG->sessioncookiedomain,
            'secure'   => is_moodle_cookie_secure(),
            'httponly' => $CFG->cookiehttponly,
        ];

        if (\core_useragent::is_chrome() && \core_useragent::check_chrome_version('78') && is_moodle_cookie_secure()) {
            // If $samesite is empty, we don't want there to be any SameSite attribute.
            $options['samesite'] = 'None';
        }

        $cookiesname = auth_plugin_relogin::get_relogin_cookies_name();

        setcookie($cookiesname, $sid, $options);
    }
}
