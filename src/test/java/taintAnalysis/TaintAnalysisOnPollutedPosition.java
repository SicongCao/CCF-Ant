package tabby.taintAnalysis;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class TaintAnalysisOnPollutedPosition {

    private static final Logger LOGGER = LoggerFactory.getLogger(TaintAnalysisOnPollutedPosition.class);

    /*使用Tabby存到CSV中的分析结果进行搜索，搜索过程中进行联通路径分析和污点分析*/

    public static void main(String[] args) {
        //从CSV中读取callGraph，demo测试CSV_example中示例，后续改为tabby存放CSV的路径
        String methodCSV = "src/main/java/tabby/taintAnalysis/CSV_example/GRAPHDB_PUBLIC_METHODS.csv";
        String callCSV = "src/main/java/tabby/taintAnalysis/CSV_example/GRAPHDB_PUBLIC_CALL.csv";
        CSVReader methodReader = null;
        CSVReader callReader = null;
        //用于接收CSV读取的结果
        HashSet<SingleMethod> Methods = new HashSet<SingleMethod>();
        HashSet<SingleLine> Lines = new HashSet<SingleLine>();
        /* 读取methods和calls信息 */
        try {
            methodReader = new CSVReader(new FileReader(methodCSV));
            //CSV中单行的信息存放再singleMethod中，后续赋值给一个singleMethod对象,对于call边的处理类似
            String[] singleMethod;
            //用于记录循环次数，并跳过CSV文件首行
            //读取method信息
            int numOfMethod = 0;
            while ((singleMethod = methodReader.readNext()) != null) {
                //跳过CSV文件首行
                if (numOfMethod == 0) {
                    numOfMethod++;
                    continue;
                }
                String methodID = singleMethod[0];
                String className = singleMethod[3];
                String methodName = singleMethod[13];
                SingleMethod method = new SingleMethod(methodID, methodName, className);
                int parameterSize = Integer.parseInt(singleMethod[14]);
                method.setParameterSize(parameterSize);
                //具体参数暂时没用上，后续应该会使用
                /*
                parameters从CSV读出是字符串，进行处理将其处理为列表,以下为几种情况示例：
                1) 多参数--> ["[0,\"java.awt.datatransfer.DataFlavor\"]","[1,\"javax.activation.DataSource\"]"]
                2) 空列表，无参数--> []
                3) 单参数--> ["[0,\"jdk.nashorn.internal.ir.BinaryNode\"]"]
                */
                String parametersLine = singleMethod[15];
                //空列表置null
                if (parametersLine.isEmpty()) {
                    method.setParameters(null);
                    numOfMethod++;
                }
                //含有“],”的为多参数--TODO
                else if (parametersLine.contains("],")) {
//                    str1 = result.substring(result.indexOf("["), result.indexOf(",", result.indexOf(",") + 1));
                    numOfMethod++;
                } else {
//                    str1 = result.substring(result.indexOf("["), result.indexOf("]") + 1);
                    numOfMethod++;
                }
                //对象赋值后加入methods
                Methods.add(method);

            }
        } catch (CsvValidationException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        //读取call边信息
        try {
            callReader = new CSVReader(new FileReader(callCSV));
            String[] singleLine;

            int numOfLine = 0;
            while ((singleLine = callReader.readNext()) != null) {
                //跳过CSV文件首行
                if (numOfLine == 0) {
                    numOfLine++;
                    continue;
                }
                String lineID = singleLine[0];
//                String source = singleLine[5];
//                String target = singleLine[6];
                //边由source指向target，但是由于下面做的是自底向上的，所以倒置边的指向
                String target = singleLine[5];
                String source = singleLine[6];
                //pollutedposition参数格式为字符串 [-1,-2,-2]， 因此去掉头尾[]后，按"，"分割
                ArrayList<Integer> pollutedPositionlist = new ArrayList<Integer>();
                for (String position : singleLine[3].replace("[", "").replace("]", "").split(",")) {
                    //String转换为int
                    pollutedPositionlist.add(Integer.parseInt(position));
//                    System.out.println(pollutedPositionlist);
                }
                //新建line对象存储CSV中提取信息并用hashset存储
                SingleLine line = new SingleLine(lineID, target, source);
                line.setPollutedPosition(pollutedPositionlist);
                Lines.add(line);
            }
        } catch (CsvValidationException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

//        提取边中信息存入method对象中，以计算联通路径，ps：后续考虑还是用动态的方式做，在搜索过程中计算,否则过于冗余
//        for (SingleMethod method : Methods) {
//            String sourceID = method.getMethodID();
//            //丑陋的嵌套循环，遍历call边集，从中提取SourceID一致的边的信息，添加到method对象中
//            //为了能在迭代中删除已经用过的边，使用迭代器
//            Iterator<SingleLine> lineSet = Lines.iterator();
//            while (lineSet.hasNext()){
//                String source = lineSet.next().getSource();
//                if (source.equals(sourceID)){
//                    //target存放下一跳方法ID
//                    String target = lineSet.next().getTarget();
//                    //pollutedPositionList存放下一跳污点参数信息
//                    ArrayList<Integer> taintList = lineSet.next().getPollutedPosition();
//                    //加入method对象中
//                    method.addNextNodes(target, taintList);
//                    //记录过的边移出set
//                    lineSet.remove();
//                    System.out.println(Lines.size());
//                }
//            }
//        }

//            for (SingleLine line : Lines) {
//                //source为边中source方法的ID
//                String source = line.getSource();
//                try {
//                    if (source.equals(sourceID)){
//                        //target存放下一跳方法ID
//                        String target = line.getTarget();
//                        //pollutedPositionList存放下一跳污点参数信息
//                        ArrayList<Integer> taintList = line.getPollutedPosition();
//                        //加入method对象中
//                        method.addNextNodes(target, taintList);
//                        System.out.println(method);
//                    }
//                } catch (Exception e){
//                    System.out.println("if err");
//                }
//                }
//            }
        //demo：从source开始执行搜索
        //存放已经搜索过的方法节点
        HashSet<SingleMethod> exploredMethods = new HashSet<>();
        //存放即将搜索的方法节点
        LinkedList<SingleMethod> methodsToExplore = new LinkedList<>();
        //获取搜索起始节点，即sink节点（自底向上）
        for (SingleMethod method : Methods) {
            if (method.isSink()) {
                methodsToExplore.add(method);
                exploredMethods.add(method);
            }
        }

        long iteration = 0;
        //执行广度优先的搜索方式自底向上搜索
        while (methodsToExplore.size() > 0) {
            if ((iteration % 1000) == 0) {
                LOGGER.info("Iteration " + iteration + ", Remain: " + methodsToExplore.size());
            }
            iteration += 1;
            //取出队列中最后一个节点
            SingleMethod method = methodsToExplore.pop();
            //判断该方法是否存在下一跳,如果有下一跳，那么判断污点是否能够传递
            method.getNextNodes(Lines);
            ArrayList lastPollutedPositions = method.pollutedPositions;
            //如果该方法存在下一跳
            if (method.isHasNextNode()) {
                for (int i = 0; i < method.nextNodes.size(); i++) {
                    //取下一跳信息
                    String nextMethodID = method.nextNodes.get(i);
                    SingleMethod nextMethod = getMethodFromID(Methods, nextMethodID);
                    //如果访问过了，跳过
                    if (exploredMethods.contains(nextMethod)) {
                        System.out.println("isExplored");
                        continue;
                    }
                    //如果没访问过，判断污点能否在该跳传播
                    if (getPollutedPosition(lastPollutedPositions, method.nextPollutedPositions.get(i)).isEmpty()) {
                        //如果污点传递为空数组，那么该跳无效
                        System.out.println("No Taint");
                        continue;
                    } else {
                        System.out.println("Has Taint");
                        //判断该方法是否为source
                        if (isSource(nextMethod)){
                            //如果是sink，那么将目前遍历的结果记录，TODO
                            LOGGER.info("Source is available");
                        }
                        else{
                            //如果能够传播但不是source，那么将pp参数的结果写入该类中，然后将该节点加入需要探索的节点集
                            nextMethod.pollutedPositions =
                                    getPollutedPosition(lastPollutedPositions, method.nextPollutedPositions.get(i));
                            methodsToExplore.add(nextMethod);
                            //这里应该有问题，什么时候记录已经访问过的节点呢？
                            exploredMethods.add(nextMethod);
                        }
                    }
                }
            }


        }
        //输出查询的结果 TODO


    }

    //判断污点能否传递，通过pp参数来确定，sink传播至其下一跳的所有参数都为污点参数
    //20220203，ps:-1也需要关注，-1指a.func(b)类似形式的调用，a就是-1
    //下一跳元素取下标，如[-1,0,1]的下一跳是[-1,1,1,1,3]那么其中在[-1,0,1]中的值，然后取下标[0，1，2，3]
    //这里有大问题，先码着 TODO
    private static ArrayList<Integer> getPollutedPosition(ArrayList<Integer> lastPP, ArrayList<Integer> nextPP) {
        ArrayList<Integer> mergedList = new ArrayList<Integer>();
        for (Integer i = 0; i < nextPP.size(); i++) {
            if (lastPP.contains(nextPP.get(i))) {
                mergedList.add(i);
            }
        }
        return mergedList;
    }

    private static SingleMethod getMethodFromID(HashSet<SingleMethod> methods, String methodID) {
        for (SingleMethod method : methods) {
            if (method.getMethodID().equals(methodID)) {
                return method;
            }
        }
        return null;
    }

    private static boolean isSource(SingleMethod method) {
        // 判断节点是否为source，通过先验知识绑定，由于在demo测试的下jar包中没发现http.requeset下的方法，
        // 所以demo中测试了反序列化调用链的source和sink

        if (method.getClassName().equals("java.lang.reflect.InvocationHandler")
                && method.getMethodName().equals("invoke")) {
            return true;
        }
        if (method.getClassName().equals("java.lang.Object")
                && method.getMethodName().equals("toString")) {
            return true;
        }
        if (method.getClassName().equals("java.lang.Object")
                && method.getMethodName().equals("hashCode")) {
            return true;
        }
        if (method.getClassName().equals("java.lang.Comparable")
                && method.getMethodName().equals("compareTo")) {
            return true;
        }
        return false;

    }


}