.class public final Llyiahf/vczjk/oaa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o:Llyiahf/vczjk/zl;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/yda;

.field public OooO0O0:J

.field public OooO0OO:Llyiahf/vczjk/zl;

.field public OooO0Oo:Z

.field public OooO0o0:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/zl;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/zl;-><init>(F)V

    sput-object v0, Llyiahf/vczjk/oaa;->OooO0o:Llyiahf/vczjk/zl;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wz8;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/wz8;->OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/oaa;->OooO00o:Llyiahf/vczjk/yda;

    const-wide/high16 v0, -0x8000000000000000L

    iput-wide v0, p0, Llyiahf/vczjk/oaa;->OooO0O0:J

    sget-object p1, Llyiahf/vczjk/oaa;->OooO0o:Llyiahf/vczjk/zl;

    iput-object p1, p0, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/qm1;Llyiahf/vczjk/rm1;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 12

    instance-of v0, p3, Llyiahf/vczjk/laa;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/laa;

    iget v1, v0, Llyiahf/vczjk/laa;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/laa;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/laa;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/laa;-><init>(Llyiahf/vczjk/oaa;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/laa;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/laa;->label:I

    sget-object v3, Llyiahf/vczjk/oaa;->OooO0o:Llyiahf/vczjk/zl;

    const-wide/high16 v4, -0x8000000000000000L

    const/4 v6, 0x0

    const/4 v7, 0x2

    const/4 v8, 0x0

    const/4 v9, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v9, :cond_2

    if-ne v2, v7, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/laa;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/le3;

    iget-object p2, v0, Llyiahf/vczjk/laa;->L$0:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/oaa;

    :try_start_0
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_6

    :catchall_0
    move-exception p1

    goto/16 :goto_8

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget p1, v0, Llyiahf/vczjk/laa;->F$0:F

    iget-object p2, v0, Llyiahf/vczjk/laa;->L$2:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/le3;

    iget-object v2, v0, Llyiahf/vczjk/laa;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object v10, v0, Llyiahf/vczjk/laa;->L$0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/oaa;

    :try_start_1
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    move-object p3, v0

    move-object v0, p2

    move-object p2, v2

    move-object v2, p3

    move-object p3, v10

    goto :goto_3

    :catchall_1
    move-exception p1

    move-object p2, v10

    goto/16 :goto_8

    :cond_3
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-boolean p3, p0, Llyiahf/vczjk/oaa;->OooO0Oo:Z

    if-eqz p3, :cond_4

    const-string p3, "animateToZero called while previous animation is running"

    invoke-static {p3}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :cond_4
    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p3

    sget-object v2, Llyiahf/vczjk/vp3;->OooOOo:Llyiahf/vczjk/vp3;

    invoke-interface {p3, v2}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/fo5;

    if-eqz p3, :cond_5

    invoke-interface {p3}, Llyiahf/vczjk/fo5;->Oooo0oO()F

    move-result p3

    goto :goto_1

    :cond_5
    const/high16 p3, 0x3f800000    # 1.0f

    :goto_1
    iput-boolean v9, p0, Llyiahf/vczjk/oaa;->OooO0Oo:Z

    move-object v2, v0

    move-object v0, p2

    move-object p2, p1

    move p1, p3

    move-object p3, p0

    :cond_6
    :try_start_2
    iget v10, p3, Llyiahf/vczjk/oaa;->OooO0o0:F

    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    move-result v10

    const v11, 0x3c23d70a    # 0.01f

    cmpg-float v10, v10, v11

    if-gez v10, :cond_7

    :goto_2
    move-object p1, p3

    move-object p3, p2

    move-object p2, p1

    move-object p1, v0

    goto :goto_4

    :cond_7
    new-instance v10, Llyiahf/vczjk/maa;

    invoke-direct {v10, p3, p1, p2}, Llyiahf/vczjk/maa;-><init>(Llyiahf/vczjk/oaa;FLlyiahf/vczjk/oe3;)V

    iput-object p3, v2, Llyiahf/vczjk/laa;->L$0:Ljava/lang/Object;

    iput-object p2, v2, Llyiahf/vczjk/laa;->L$1:Ljava/lang/Object;

    iput-object v0, v2, Llyiahf/vczjk/laa;->L$2:Ljava/lang/Object;

    iput p1, v2, Llyiahf/vczjk/laa;->F$0:F

    iput v9, v2, Llyiahf/vczjk/laa;->label:I

    invoke-interface {v2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v11

    invoke-static {v11}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v11

    invoke-interface {v11, v2, v10}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object v10

    if-ne v10, v1, :cond_8

    goto :goto_5

    :cond_8
    :goto_3
    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    cmpg-float v10, p1, v6

    if-nez v10, :cond_6

    goto :goto_2

    :goto_4
    :try_start_3
    iget v0, p2, Llyiahf/vczjk/oaa;->OooO0o0:F

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    cmpg-float v0, v0, v6

    if-nez v0, :cond_9

    goto :goto_7

    :cond_9
    new-instance v0, Llyiahf/vczjk/naa;

    invoke-direct {v0, p2, p3}, Llyiahf/vczjk/naa;-><init>(Llyiahf/vczjk/oaa;Llyiahf/vczjk/oe3;)V

    iput-object p2, v2, Llyiahf/vczjk/laa;->L$0:Ljava/lang/Object;

    iput-object p1, v2, Llyiahf/vczjk/laa;->L$1:Ljava/lang/Object;

    const/4 p3, 0x0

    iput-object p3, v2, Llyiahf/vczjk/laa;->L$2:Ljava/lang/Object;

    iput v7, v2, Llyiahf/vczjk/laa;->label:I

    invoke-interface {v2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p3

    invoke-static {p3}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object p3

    invoke-interface {p3, v2, v0}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_a

    :goto_5
    return-object v1

    :cond_a
    :goto_6
    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_7
    iput-wide v4, p2, Llyiahf/vczjk/oaa;->OooO0O0:J

    iput-object v3, p2, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    iput-boolean v8, p2, Llyiahf/vczjk/oaa;->OooO0Oo:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_2
    move-exception p1

    move-object p2, p3

    :goto_8
    iput-wide v4, p2, Llyiahf/vczjk/oaa;->OooO0O0:J

    iput-object v3, p2, Llyiahf/vczjk/oaa;->OooO0OO:Llyiahf/vczjk/zl;

    iput-boolean v8, p2, Llyiahf/vczjk/oaa;->OooO0Oo:Z

    throw p1
.end method
