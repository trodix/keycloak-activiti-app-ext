/*
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.inteligr8.activiti;

/**
 * This interface is for defining utilities that provide data-based fixes to
 * APS deployments.
 * 
 * @author brian@inteligr8.com
 */
public interface DataFixer {
	
	/**
	 * The method called when the framework wants to execute the fix.  This
	 * will be called only on startup; and on every startup.
	 */
	void fix();

}
