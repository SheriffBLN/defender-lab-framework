Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 -AttackSurfaceReductionRules_Actions AuditMode
$filterName = "TestFilterSimple"
$consumerName = "TestConsumerSimple"

$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name           = $filterName
    EventNamespace = "root\\cimv2"
    QueryLanguage  = "WQL"
    Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime'"
}

$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name = $consumerName
    CommandLineTemplate = "cmd.exe /c echo Test_ASR > C:\\Temp\\asr_test_output.txt"
}

$filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq $filterName }
$consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq $consumerName }

$binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter   = $filter.__PATH
    Consumer = $consumer.__PATH
}
Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*TestFilterSimple*" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "TestConsumerSimple" } | Remove-WmiObject
Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "TestFilterSimple" } | Remove-WmiObject
