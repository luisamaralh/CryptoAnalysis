package crypto.reporting;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.google.common.collect.Table;

import crypto.analysis.IAnalysisSeed;
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.ErrorWithObjectAllocation;
import crypto.rules.CrySLRule;
import soot.SootClass;
import soot.SootMethod;

public class ReporterHelper{

	/** Generates analysis report content for {@link CommandLineReporter} and {@link TXTReporter}
	 * @param rules a {@link List} with {@link CrySLRule} rules
	 * @param objects a{@link Collection} with {@link IAnalysisSeed} objects
	 * @param secureObjects a {@link List} with {@link IAnalysisSeed} secureObjects
	 * @param errorMarkers a {@link Table} containing {@link SootClass},{@link SootMethod} 
	 * and a {@link Set} of {@link AbstractError} of the errors found during analysis
	 * @param errorMarkerCount a {@link Map} containing {@link Class} class of error and 
	 * {@link Integer} number of errors
	 * @return report {@link String} of the analysis
	 */
	public static String generateReport(List<CrySLRule> rules, Collection<IAnalysisSeed> objects, 
			List<IAnalysisSeed> secureObjects, Table<SootClass, SootMethod, Set<AbstractError>> errorMarkers, 
			Map<Class, Integer> errorMarkerCount) {
		String report = "";

//		report += "Ruleset: \n";
//		for (CrySLRule r : rules) {
//			report += String.format("\t%s\n", r.getClassName());
//		}

//		report += "\n";

//		report += "Analyzed Objects: \n";
//		int i=1;
//		for (IAnalysisSeed r : objects) {
//			report += String.format("Object: (%s)", i);
//			report += String.format("\tVariable: %s", r.var().value());
//			report += String.format("\tType: %s", r.getType());
//			report += String.format("\tStatement: %s", r.stmt().getUnit().get());
//			report += String.format("\tMethod: %s", r.getMethod());
//			report += String.format("\tSHA-256: %s", r.getObjectId());
//			report += String.format("\tSecure: %s\n", secureObjects.contains(r));
//			i++;
//		}


//		report += "\n";
//		i=1;
		report += String.format("ErrorType;Class;Method;ViolatedRule;Object;Statement\n");
		for (SootClass c : errorMarkers.rowKeySet()) {
//			report += String.format("Findings in Java Class: (%s)", i);
//			report += String.format("\tClass: %s", c.getName());
			for (Entry<SootMethod, Set<AbstractError>> e : errorMarkers.row(c).entrySet()) {
//				report += String.format("\nMethod: (%s)", j);
//				report += String.format("\tMethod: %s", e.getKey().getSubSignature());
				for (AbstractError marker : e.getValue()) {
					report += String.format("%s;", marker.getClass().getSimpleName());
					report += String.format("%s;", c.getName());
					report += String.format("%s;", e.getKey().getSubSignature());
					report += String.format("violating CrySL rule for %s", marker.getRule().getClassName());
					if (marker instanceof ErrorWithObjectAllocation) {
						report += String.format(" (on Object #%s);", ((ErrorWithObjectAllocation) marker).getObjectLocation().getObjectId());
					} else {
						report += " ;";
					}
					report += String.format("%s;", marker.toErrorMarkerString());
					report += String.format("%s\n", marker.getErrorLocation().getUnit().get());
				}
			}
		}
		return report;
	}

	public static String generateSummary(List<CrySLRule> rules, Collection<IAnalysisSeed> objects,
										List<IAnalysisSeed> secureObjects, Table<SootClass, SootMethod, Set<AbstractError>> errorMarkers,
										Map<Class, Integer> errorMarkerCount) {
		String report = "";
		report += String.format("CrySL-Rules;Objects-Analyzed;Violations\n");
		report += String.format("%s;", rules.size());
		report += String.format("%s;", objects.size());

		if(errorMarkers.rowKeySet().isEmpty()){
			report += "0\n";
		} else{
			int sumErrors=0;
			for(Entry<Class, Integer> e : errorMarkerCount.entrySet()){
				sumErrors+=e.getValue();
//				report += String.format("%s: %s;", e.getKey().getSimpleName(),e.getValue());
			}
			report += String.format("%s\n", sumErrors);
		}
		return report;
	}
	
}
