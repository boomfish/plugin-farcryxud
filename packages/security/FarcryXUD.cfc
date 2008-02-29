<cfcomponent displayname="External Farcry User Directory" hint="Provides an interface to a FarCry user directory in another database" extends="farcry.core.packages.security.UserDirectory" output="false" key="FarcryXUD" bEncrypted="false">
	
	<!--- ====================
	  UD Interface functions
	===================== --->
	<cffunction name="getLoginForm" access="public" output="false" returntype="string" hint="Returns the form component to use for login">
		
		<cfreturn "farLogin" />
	</cffunction>
	
	<cffunction name="authenticate" access="public" output="false" returntype="struct" hint="Attempts to process a user. Runs every time the login form is loaded.">
		<cfset var stResult = structnew() />
		<cfset var stProperties = structnew() />
		<cfset var qUser = "" />
		
		<cfimport taglib="/farcry/core/tags/formtools" prefix="ft" />
		
		<!--- Return struct --->
		<cfset stResult.userid = "" />
		<cfset stResult.authenticated = false />
		<cfset stResult.message = "FarcryXUD has not been configured" />
		
		<ft:processform>
			<ft:processformObjects typename="#getLoginForm()#">
				<cfif not len(application.config.farcryxud['#this.key#dsn'])>
					<cfreturn stResult />
				</cfif>
				
				<!--- If password encryption is enabled, hash the password --->
				<cfif this.bEncrypted>
					<cfset stProperties.password = hash(stLogin.password) />
				</cfif>
				
				<!--- Find the user --->
				<cfquery datasource="#application.config.farcryxud['#this.key#dsn']#" name="qUser">
					select	*
					from	#application.config.farcryxud['#this.key#dbowner']#farUser
					where	userid=<cfqueryparam cfsqltype="cf_sql_varchar" value="#stProperties.username#" />
							and password=<cfqueryparam cfsqltype="cf_sql_varchar" value="#stProperties.password#" />
				</cfquery>
				
				<cfset stResult.userid = stProperties.username />
			</ft:processformObjects>
		</ft:processform>
		
		<!--- If (somehow) a login was submitted, process the result --->
		<cfif isquery(qUser)>
		
	        <cfset dateTolerance = DateAdd("n","-#application.config.farcryxud['#this.key#loginAttemptsTimeOut']#",Now()) />
	        
	        <cfquery name="qLogAudit" datasource="#application.config.farcryxud['#this.key#dsn']#">
		        select		count(datetimecreated) as numberOfLogin, max(datetimecreated) as lastlogindate, userid
		        from		#application.config.farcryxud['#this.key#dbowner']#farLog
		        where		type='security'
		       				and event='loginfailed'
		            		and datetimecreated >= <cfqueryparam value="#createODBCDateTime(dateTolerance)#" cfsqltype="cf_sql_timestamp" />
		            		and userid = <cfqueryparam cfsqltype="cf_sql_varchar" value="#qUser.userid#_CLIENTUD" />
		        group by	userid
	        </cfquery>
					
			<!--- Set the result --->
			<cfif qLogAudit.numberOfLogin gte application.config.farcryxud['#this.key#loginAttemptsAllowed']>
				<!--- User is locked out due to high number of failed logins recently --->
				<cfset stResult.authenticated = false />
				<cfset stResult.message = "Your account has been locked due to a high number of failed logins. It will be unlocked automatically in #application.config.general.loginAttemptsTimeOut# minutes." />
			<cfelseif qUser.recordcount and qUser.userstatus eq "active">
				<!--- User successfully logged in --->
				<cfset stResult.authenticated = true />
			<cfelseif qUser.recordcount>
				<!--- User's account is disabled --->
				<cfset stResult.authenticated = false />
				<cfset stResult.message = "Your account is disabled" />
			<cfelse>
				<!--- User login or password is incorrect --->
				<cfset stResult.authenticated = false />
				<cfset stResult.message = "The username or password was incorrect">
			</cfif>
			
			<cfif not stResult.authenticated>
				<cfquery datasource="#application.config.farcryxud['#this.key#dsn']#">
					insert into farLog (
						objectid,
						label,
						datetimecreated,
						createdby,
						ownedby,
						datetimelastupdated,
						lastupdatedby,
						lockedby,
						locked,
						object,
						type,
						event,
						location,
						userid,
						ipaddress,
						notes
					)
					values (
						<cfqueryparam cfsqltype="cf_sql_varchar" value="#createuuid()#" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="" />,
						<cfqueryparam cfsqltype="cf_sql_date" value="#now()#" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="" />,
						<cfqueryparam cfsqltype="cf_sql_date" value="#now()#" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="" />,
						<cfqueryparam cfsqltype="cf_sql_bit" value="0" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="security" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="loginfailed" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="#getCurrentTemplatePath()#" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="#stResult.userid#_CLIENTUD" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="#cgi.REMOTE_ADDR#" />,
						<cfqueryparam cfsqltype="cf_sql_varchar" value="External login (#application.applicationname#): #stResult.message#" />
					)
				</cfquery>
			</cfif>
		
		</cfif>
		
		<cfreturn stResult />
	</cffunction>
	
	<cffunction name="getUserGroups" access="public" output="false" returntype="array" hint="Returns the groups that the specified user is a member of">
		<cfargument name="UserID" type="string" required="true" hint="The user being queried" />
		
		<cfset var qGroups = "" />
		<cfset var aGroups = arraynew(1) />
		
		<cfif not len(application.config.farcryxud['#this.key#dsn'])>
			<cfreturn aGroups />
		</cfif>
		
		<cfquery datasource="#application.config.farcryxud['#this.key#dsn']#" name="qGroups">
			select	g.title
			from	(
						#application.config.farcryxud['#this.key#dbowner']#farUser u
						inner join
						#application.config.farcryxud['#this.key#dbowner']#farUser_aGroups ug
						on u.objectid=ug.parentid
					)
					inner join
					#application.config.farcryxud['#this.key#dbowner']#farGroup g
					on ug.data=g.objectid
			where	userid=<cfqueryparam cfsqltype="cf_sql_varchar" value="#arguments.userid#" />
		</cfquery>
		
		<cfloop query="qGroups">
			<cfset arrayappend(aGroups,title) />
		</cfloop>
		
		<cfreturn aGroups />
	</cffunction>
	
	<cffunction name="getAllGroups" access="public" output="false" returntype="array" hint="Returns all the groups that this user directory supports">
		<cfset var qGroups = "" />
		<cfset var aGroups = arraynew(1) />
		
		<cfif not len(application.config.farcryxud['#this.key#dsn'])>
			<cfreturn aGroups />
		</cfif>
		
		<cfquery datasource="#application.config.farcryxud['#this.key#dsn']#" name="qGroups">
			select		*
			from		#application.config.farcryxud['#this.key#dbowner']#farGroup
			order by	title
		</cfquery>
		
		<cfloop query="qGroups">
			<cfset arrayappend(aGroups,title) />
		</cfloop>

		<cfreturn aGroups />
	</cffunction>

	<cffunction name="getGroupUsers" access="public" output="false" returntype="array" hint="Returns all the users in a specified group">
		<cfargument name="group" type="string" required="true" hint="The group to query" />
		
		<cfset var qUsers = "" />
		
		<cfif not len(application.config.farcryxud['#this.key#dsn'])>
			<cfreturn arraynew(1) />
		</cfif>
		
		<cfquery datasource="#application.config.farcryxud['#this.key#dsn']#" name="qUsers">
			select	userid
			from	(
						#application.config.farcryxud['#this.key#dbowner']#farUser u
						inner join
						#application.config.farcryxud['#this.key#dbowner']#farUser_aGroups ug
						on u.objectid=ug.parentid
					)
					inner join
					#application.config.farcryxud['#this.key#dbowner']#farGroup g
					on ug.data=g.objectid
			where	g.title=<cfqueryparam cfsqltype="cf_sql_varchar" value="#arguments.group#" />
		</cfquery>
		
		<cfreturn listtoarray(valuelist(qUsers.userid)) />
	</cffunction>
	
	<cffunction name="getProfile" access="public" output="false" returntype="struct" hint="Returns profile data available through the user directory">
		<cfargument name="userid" type="string" required="true" hint="The user directory specific user id" />
		
		<cfset var prop = "" />
		<cfset var stResult = structnew() />

		<cfif not len(application.config.farcryxud['#this.key#dsn'])>
			<cfreturn stResult />
		</cfif>

		<cfquery datasource="#application.config.farcryxud['#this.key#dsn']#" name="qProfile">
			select	*
			from	#application.config.farcryxud['#this.key#dbowner']#dmProfile
			where	username=<cfqueryparam cfsqltype="cf_sql_varchar" value="#arguments.userid#" />
		</cfquery>
		
		<cfloop list="#application.factory.oUtils.listDiff('objectid,createdby,datetimecreated,ownedby,datetimelastupdated,lastupdatedby,lockedBy,locked,userdirectory,username,overviewHome',qProfile.columnlist)#" index="prop">
			<cfset stResult[prop] = qProfile[prop][1] />
		</cfloop>
		
		<cfset stResult.override = false />
		
		<cfreturn stResult />
	</cffunction>
	
</cfcomponent>