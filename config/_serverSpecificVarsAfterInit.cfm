<cfsetting enablecfoutputonly="true" />
<!--- @@displayname: Set up XUD --->

<cfif structkeyexists(application.config,"farcryxud")>
	<cfloop collection="#application.config.farcryxud#" item="configitem">
		<cfif right(configitem,5) eq "title" and structkeyexists(application.security.userdirectories,left(configitem,len(configitem)-5))>
			<cfset application.security.userdirectories[left(configitem,len(configitem)-5)].title = application.config.farcryxud[configitem] />
		</cfif>
	</cfloop>
</cfif>

<cfsetting enablecfoutputonly="false" />