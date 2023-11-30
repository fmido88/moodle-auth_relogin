# ReLogin #

In Moodle session Manger, the cookies saved is a session cookies which will be deleted when the browser closed or becomes inactive which bothers some users as they have to re-login again even if the session is not expired, this plugin provide auto login mechanism to re-login the users with unexpired sessions.

This plugin works as when user logged in, it saves a permanent cookies with the same session id, so when the user opens the browser again the plugin searches for that cookie and check for this session if not expired uet, and re-login the user again automatically.

Admins can decided which technique will be used or both.

Cookies stored by this plugin expires if the user normally logged out.

## Installing via uploaded ZIP file ##

1. Log in to your Moodle site as an admin and go to _Site administration >
   Plugins > Install plugins_.
2. Upload the ZIP file with the plugin code. You should only be prompted to add
   extra details if your plugin type is not automatically detected.
3. Check the plugin validation report and finish the installation.

## Installing manually ##

The plugin can be also installed by putting the contents of this directory to

    {your/moodle/dirroot}/auth/relogin

Afterwards, log in to your Moodle site as an admin and go to _Site administration >
Notifications_ to complete the installation.

Alternatively, you can run

    $ php admin/cli/upgrade.php

to complete the installation from the command line.

## License ##

2023 Mohammad Farouk <phun.for.physics@gmail.com>

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program.  If not, see <https://www.gnu.org/licenses/>.
