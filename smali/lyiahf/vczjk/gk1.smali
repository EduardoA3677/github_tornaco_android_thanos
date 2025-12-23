.class public final Llyiahf/vczjk/gk1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $delegate:Llyiahf/vczjk/b25;

.field final synthetic $workConstraintsTracker:Llyiahf/vczjk/aqa;

.field final synthetic $workSpec:Llyiahf/vczjk/ara;

.field label:I

.field final synthetic this$0:Landroidx/work/impl/workers/ConstraintTrackingWorker;


# direct methods
.method public constructor <init>(Landroidx/work/impl/workers/ConstraintTrackingWorker;Llyiahf/vczjk/b25;Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gk1;->this$0:Landroidx/work/impl/workers/ConstraintTrackingWorker;

    iput-object p2, p0, Llyiahf/vczjk/gk1;->$delegate:Llyiahf/vczjk/b25;

    iput-object p3, p0, Llyiahf/vczjk/gk1;->$workConstraintsTracker:Llyiahf/vczjk/aqa;

    iput-object p4, p0, Llyiahf/vczjk/gk1;->$workSpec:Llyiahf/vczjk/ara;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/gk1;

    iget-object v1, p0, Llyiahf/vczjk/gk1;->this$0:Landroidx/work/impl/workers/ConstraintTrackingWorker;

    iget-object v2, p0, Llyiahf/vczjk/gk1;->$delegate:Llyiahf/vczjk/b25;

    iget-object v3, p0, Llyiahf/vczjk/gk1;->$workConstraintsTracker:Llyiahf/vczjk/aqa;

    iget-object v4, p0, Llyiahf/vczjk/gk1;->$workSpec:Llyiahf/vczjk/ara;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/gk1;-><init>(Landroidx/work/impl/workers/ConstraintTrackingWorker;Llyiahf/vczjk/b25;Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gk1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gk1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gk1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/gk1;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gk1;->this$0:Landroidx/work/impl/workers/ConstraintTrackingWorker;

    iget-object v1, p0, Llyiahf/vczjk/gk1;->$delegate:Llyiahf/vczjk/b25;

    iget-object v3, p0, Llyiahf/vczjk/gk1;->$workConstraintsTracker:Llyiahf/vczjk/aqa;

    iget-object v4, p0, Llyiahf/vczjk/gk1;->$workSpec:Llyiahf/vczjk/ara;

    iput v2, p0, Llyiahf/vczjk/gk1;->label:I

    invoke-static {p1, v1, v3, v4, p0}, Landroidx/work/impl/workers/ConstraintTrackingWorker;->OooO0Oo(Landroidx/work/impl/workers/ConstraintTrackingWorker;Llyiahf/vczjk/b25;Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    return-object p1
.end method
