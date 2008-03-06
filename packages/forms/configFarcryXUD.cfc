<cfcomponent displayname="FarCry XUD" hint="FarCry external user directory settings" extends="farcry.core.packages.forms.forms" output="false" key="farcryxud">
	<cfproperty ftSeq="1" ftFieldset="FarCry XUD" name="farcryxudtitle" type="string" default="External User Directory" hint="Title of external directory" ftLabel="Title" ftType="string" />
	<cfproperty ftSeq="2" ftFieldset="FarCry XUD" name="farcryxuddsn" type="string" default="" hint="Datasource of external FarCry DB" ftLabel="DSN" ftType="string" />
	<cfproperty ftSeq="3" ftFieldset="FarCry XUD" name="farcryxuddbowner" type="string" default="" hint="DB owner of external FarCry DB" ftLabel="DB Owner" ftType="string" />
	<cfproperty ftSeq="4" ftFieldset="FarCry XUD" name="farcryxudloginAttemptsTimeOut" type="numeric" default="10" hint="The amount of time it takes for failed logins to time out" ftLabel="Login Attempts Timeout" ftType="integer" />
	<cfproperty ftSeq="5" ftFieldset="FarCry XUD" name="farcryxudloginAttemptsAllowed" type="numeric" default="3" hint="The number of failed logins that should triger lockout" ftLabel="Login Attempts Allowed" ftType="integer" />
	
</cfcomponent>