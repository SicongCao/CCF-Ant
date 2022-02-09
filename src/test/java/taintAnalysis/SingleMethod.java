package tabby.taintAnalysis;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;

public class SingleMethod {

    private String methodID;
    private String methodName;
    private String className;
    private int parameterSize;
    private ArrayList<String> parameters;
    //用于记录下一跳的信息，以进行联通分析
    public ArrayList<Integer> pollutedPositions;
    public ArrayList<String> nextNodes;
    public ArrayList<ArrayList<Integer>> nextPollutedPositions;
    private boolean hasNextNode;


    public SingleMethod(String methodID, String methodName, String className) {
        this.methodID = methodID;
        this.methodName = methodName;
        this.className = className;
        this.nextNodes = new ArrayList<String>();
        this.nextPollutedPositions = new ArrayList<ArrayList<Integer>>();
        this.hasNextNode = false;
        this.pollutedPositions = new ArrayList<Integer>();
        //如果是sink，demo测试时为了方便测试，默认将所有的参数和调用本身都视为污点
        if (isSink()) {
            this.pollutedPositions.add(-1);
            for (int i = 0; i < this.getParameterSize(); i++) {
                this.pollutedPositions.add(i);
            }
//            System.out.println(this.pollutedPositions);
        }
    }

    //判断节点是否为Sink，通过先验知识给定，demo中仅作测试，Sink中可控点的污点需要先验知识给定，这里先假定所有的参数都是可控的
    public boolean isSink() {
        if (this.getClassName().equals("java.io.FileInputStream")
                && this.getMethodName().equals("<init>")) {
            return true;
        }
        if (this.getClassName().equals("java.io.FileOutputStream")
                && this.getMethodName().equals("<init>")) {
            return true;
        }
        if (this.getClassName().equals("java.nio.file.Files")
                && (this.getMethodName().equals("newInputStream")
                || this.getMethodName().equals("newOutputStream")
                || this.getMethodName().equals("newBufferedReader")
                || this.getMethodName().equals("newBufferedWriter"))) {
            return true;
        }

        if (this.getClassName().equals("java.lang.Runtime")
                && this.getMethodName().equals("exec")) {
            return true;
        }
        if (this.getClassName().equals("java.lang.reflect.Method")
                && this.getMethodName().equals("invoke") && this.getParameterSize() == 0) {
            return true;
        }
        if (this.getClassName().equals("java.net.URLClassLoader")
                && this.getMethodName().equals("newInstance")) {
            return true;
        }
        if (this.getClassName().equals("java.lang.System")
                && this.getMethodName().equals("exit")) {
            return true;
        }
        if (this.getClassName().equals("java.lang.Shutdown")
                && this.getMethodName().equals("exit")) {
            return true;
        }
        if (this.getClassName().equals("java.lang.Runtime")
                && this.getMethodName().equals("exit")) {
            return true;
        }

        if (this.getClassName().equals("java.nio.file.Files")
                && this.getMethodName().equals("newOutputStream")) {
            return true;
        }


        if (this.getClassName().equals("java.net.URL")
                && this.getMethodName().equals("openStream")) {
            return true;
        }

        //都不是则返回false
        return false;
    }

    public void setPollutedPositions(ArrayList<Integer> pollutedPositions){
        this.pollutedPositions = pollutedPositions;
    }

    //添加新的下一跳信息
    public void addNextNodes(String methodID, ArrayList<Integer> pollutedPositionList) {
        this.nextNodes.add(methodID);
        this.nextPollutedPositions.add(pollutedPositionList);
    }

    //获取下一跳的信息
    public void getNextNodes(HashSet<SingleLine> Lines) {
        String sourceID = this.methodID;
        Iterator<SingleLine> lineSet = Lines.iterator();
        while (lineSet.hasNext()) {
            String source = lineSet.next().getSource();
            if (source.equals(sourceID)) {
                //target存放下一跳方法ID
                String target = lineSet.next().getTarget();
                //pollutedPositionList存放下一跳污点参数信息
                ArrayList<Integer> taintList = lineSet.next().getPollutedPosition();
                //加入method对象中
                this.addNextNodes(target, taintList);
                //记录过的边移出set
                lineSet.remove();
                //记录该方法存在下一跳
                this.hasNextNode = true;
            }
        }
    }
    //判断是否存在下一跳
    public boolean isHasNextNode() {
        return hasNextNode;
    }


    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public void setMethodID(String methodID) {
        this.methodID = methodID;
    }

    public void setParameters(ArrayList<String> parameters) {
        this.parameters = parameters;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public void setParameterSize(int parameterSize) {
        this.parameterSize = parameterSize;
    }

    public int getParameterSize() {
        return parameterSize;
    }

    public List getParameters() {
        return parameters;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getMethodID() {
        return methodID;
    }

    public String getClassName() {
        return className;
    }
}