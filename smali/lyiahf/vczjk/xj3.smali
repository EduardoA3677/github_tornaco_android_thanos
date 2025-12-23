.class public final Llyiahf/vczjk/xj3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j88;
.implements Llyiahf/vczjk/pa6;
.implements Llyiahf/vczjk/gs2;


# static fields
.field public static final OooOoOO:Ljava/lang/String;


# instance fields
.field public final OooOOO:Ljava/util/HashMap;

.field public final OooOOO0:Landroid/content/Context;

.field public final OooOOOO:Llyiahf/vczjk/i52;

.field public OooOOOo:Z

.field public final OooOOo:Llyiahf/vczjk/xo8;

.field public final OooOOo0:Ljava/lang/Object;

.field public final OooOOoo:Llyiahf/vczjk/n77;

.field public final OooOo:Llyiahf/vczjk/aqa;

.field public final OooOo0:Llyiahf/vczjk/wh1;

.field public final OooOo00:Llyiahf/vczjk/bp8;

.field public final OooOo0O:Ljava/util/HashMap;

.field public OooOo0o:Ljava/lang/Boolean;

.field public final OooOoO:Llyiahf/vczjk/zr9;

.field public final OooOoO0:Llyiahf/vczjk/rqa;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "GreedyScheduler"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/wh1;Llyiahf/vczjk/qx9;Llyiahf/vczjk/n77;Llyiahf/vczjk/bp8;Llyiahf/vczjk/rqa;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOOO:Ljava/util/HashMap;

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOOo0:Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/fk7;

    invoke-direct {v0}, Llyiahf/vczjk/fk7;-><init>()V

    new-instance v1, Llyiahf/vczjk/xo8;

    invoke-direct {v1, v0}, Llyiahf/vczjk/xo8;-><init>(Llyiahf/vczjk/fk7;)V

    iput-object v1, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0O:Ljava/util/HashMap;

    iput-object p1, p0, Llyiahf/vczjk/xj3;->OooOOO0:Landroid/content/Context;

    iget-object p1, p2, Llyiahf/vczjk/wh1;->OooO0oO:Llyiahf/vczjk/sw7;

    new-instance v0, Llyiahf/vczjk/i52;

    iget-object v1, p2, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/i52;-><init>(Llyiahf/vczjk/xj3;Llyiahf/vczjk/sw7;Llyiahf/vczjk/vp3;)V

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOOOO:Llyiahf/vczjk/i52;

    new-instance v0, Llyiahf/vczjk/zr9;

    invoke-direct {v0, p1, p5}, Llyiahf/vczjk/zr9;-><init>(Llyiahf/vczjk/sw7;Llyiahf/vczjk/bp8;)V

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOoO:Llyiahf/vczjk/zr9;

    iput-object p6, p0, Llyiahf/vczjk/xj3;->OooOoO0:Llyiahf/vczjk/rqa;

    new-instance p1, Llyiahf/vczjk/aqa;

    invoke-direct {p1, p3}, Llyiahf/vczjk/aqa;-><init>(Llyiahf/vczjk/qx9;)V

    iput-object p1, p0, Llyiahf/vczjk/xj3;->OooOo:Llyiahf/vczjk/aqa;

    iput-object p2, p0, Llyiahf/vczjk/xj3;->OooOo0:Llyiahf/vczjk/wh1;

    iput-object p4, p0, Llyiahf/vczjk/xj3;->OooOOoo:Llyiahf/vczjk/n77;

    iput-object p5, p0, Llyiahf/vczjk/xj3;->OooOo00:Llyiahf/vczjk/bp8;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ara;Llyiahf/vczjk/al1;)V
    .locals 7

    invoke-static {p1}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object p1

    instance-of v0, p2, Llyiahf/vczjk/yk1;

    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOo00:Llyiahf/vczjk/bp8;

    iget-object v2, p0, Llyiahf/vczjk/xj3;->OooOoO:Llyiahf/vczjk/zr9;

    sget-object v3, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    if-eqz v0, :cond_0

    invoke-virtual {v4, p1}, Llyiahf/vczjk/xo8;->OooO00o(Llyiahf/vczjk/jqa;)Z

    move-result p2

    if-nez p2, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v5, "Constraints met: Scheduling work ID "

    invoke-direct {v0, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2, v3, v0}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v4, p1}, Llyiahf/vczjk/xo8;->OooOOO(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    move-result-object p1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/zr9;->OooO0O0(Llyiahf/vczjk/g29;)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/oOO0;

    const/4 v0, 0x0

    const/16 v2, 0x11

    invoke-direct {p2, v1, p1, v2, v0}, Llyiahf/vczjk/oOO0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iget-object p1, v1, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rqa;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/rqa;->OooO00o(Ljava/lang/Runnable;)V

    return-void

    :cond_0
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "Constraints not met: Cancelling work ID "

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v0, v3, v5}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v4, p1}, Llyiahf/vczjk/xo8;->OooOOO0(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    move-result-object p1

    if-eqz p1, :cond_1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/zr9;->OooO00o(Llyiahf/vczjk/g29;)V

    check-cast p2, Llyiahf/vczjk/zk1;

    iget p2, p2, Llyiahf/vczjk/zk1;->OooO00o:I

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/bp8;->OooO00o(Llyiahf/vczjk/g29;I)V

    :cond_1
    return-void
.end method

.method public final OooO0O0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final varargs OooO0OO([Llyiahf/vczjk/ara;)V
    .locals 13

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0o:Ljava/lang/Boolean;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOO0:Landroid/content/Context;

    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOo0:Llyiahf/vczjk/wh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/m77;->OooO00o(Landroid/content/Context;Llyiahf/vczjk/wh1;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0o:Ljava/lang/Boolean;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0o:Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    const-string v1, "Ignoring schedule request in a secondary process"

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/o55;->OooOOO0(Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/xj3;->OooOOOo:Z

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOoo:Llyiahf/vczjk/n77;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/n77;->OooO00o(Llyiahf/vczjk/gs2;)V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/xj3;->OooOOOo:Z

    :cond_2
    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    new-instance v1, Ljava/util/HashSet;

    invoke-direct {v1}, Ljava/util/HashSet;-><init>()V

    array-length v2, p1

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_b

    aget-object v5, p1, v4

    invoke-static {v5}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/xo8;->OooO00o(Llyiahf/vczjk/jqa;)Z

    move-result v6

    if-eqz v6, :cond_3

    goto/16 :goto_2

    :cond_3
    iget-object v6, p0, Llyiahf/vczjk/xj3;->OooOOo0:Ljava/lang/Object;

    monitor-enter v6

    :try_start_0
    invoke-static {v5}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v7

    iget-object v8, p0, Llyiahf/vczjk/xj3;->OooOo0O:Ljava/util/HashMap;

    invoke-virtual {v8, v7}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/wj3;

    if-nez v8, :cond_4

    new-instance v8, Llyiahf/vczjk/wj3;

    iget v9, v5, Llyiahf/vczjk/ara;->OooOO0O:I

    iget-object v10, p0, Llyiahf/vczjk/xj3;->OooOo0:Llyiahf/vczjk/wh1;

    iget-object v10, v10, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v10

    invoke-direct {v8, v9, v10, v11}, Llyiahf/vczjk/wj3;-><init>(IJ)V

    iget-object v9, p0, Llyiahf/vczjk/xj3;->OooOo0O:Ljava/util/HashMap;

    invoke-virtual {v9, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :catchall_0
    move-exception p1

    goto/16 :goto_3

    :cond_4
    :goto_1
    iget-wide v9, v8, Llyiahf/vczjk/wj3;->OooO0O0:J

    iget v7, v5, Llyiahf/vczjk/ara;->OooOO0O:I

    iget v8, v8, Llyiahf/vczjk/wj3;->OooO00o:I

    sub-int/2addr v7, v8

    add-int/lit8 v7, v7, -0x5

    invoke-static {v7, v3}, Ljava/lang/Math;->max(II)I

    move-result v7

    int-to-long v7, v7

    const-wide/16 v11, 0x7530

    mul-long/2addr v7, v11

    add-long/2addr v7, v9

    monitor-exit v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v5}, Llyiahf/vczjk/ara;->OooO00o()J

    move-result-wide v9

    invoke-static {v9, v10, v7, v8}, Ljava/lang/Math;->max(JJ)J

    move-result-wide v6

    iget-object v8, p0, Llyiahf/vczjk/xj3;->OooOo0:Llyiahf/vczjk/wh1;

    iget-object v8, v8, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v8

    iget-object v10, v5, Llyiahf/vczjk/ara;->OooO0O0:Llyiahf/vczjk/lqa;

    sget-object v11, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    if-ne v10, v11, :cond_a

    cmp-long v8, v8, v6

    if-gez v8, :cond_6

    iget-object v8, p0, Llyiahf/vczjk/xj3;->OooOOOO:Llyiahf/vczjk/i52;

    if-eqz v8, :cond_a

    iget-object v9, v8, Llyiahf/vczjk/i52;->OooO0Oo:Ljava/util/HashMap;

    iget-object v10, v5, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-virtual {v9, v10}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/Runnable;

    iget-object v11, v8, Llyiahf/vczjk/i52;->OooO0O0:Llyiahf/vczjk/sw7;

    if-eqz v10, :cond_5

    iget-object v12, v11, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v12, Landroid/os/Handler;

    invoke-virtual {v12, v10}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    :cond_5
    new-instance v10, Llyiahf/vczjk/js2;

    const/16 v12, 0x8

    invoke-direct {v10, v12, v8, v5}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object v5, v5, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-virtual {v9, v5, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v5, v8, Llyiahf/vczjk/i52;->OooO0OO:Llyiahf/vczjk/vp3;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v8

    sub-long/2addr v6, v8

    iget-object v5, v11, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v5, Landroid/os/Handler;

    invoke-virtual {v5, v10, v6, v7}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    goto/16 :goto_2

    :cond_6
    invoke-virtual {v5}, Llyiahf/vczjk/ara;->OooO0OO()Z

    move-result v6

    if-eqz v6, :cond_9

    iget-object v6, v5, Llyiahf/vczjk/ara;->OooOO0:Llyiahf/vczjk/qk1;

    iget-boolean v7, v6, Llyiahf/vczjk/qk1;->OooO0Oo:Z

    if-eqz v7, :cond_7

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    new-instance v8, Ljava/lang/StringBuilder;

    const-string v9, "Ignoring "

    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v5, ". Requires device idle."

    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v6, v7, v5}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_7
    invoke-virtual {v6}, Llyiahf/vczjk/qk1;->OooO00o()Z

    move-result v6

    if-eqz v6, :cond_8

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    new-instance v8, Ljava/lang/StringBuilder;

    const-string v9, "Ignoring "

    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v5, ". Requires ContentUri triggers."

    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v6, v7, v5}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_2

    :cond_8
    invoke-virtual {v0, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    iget-object v5, v5, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-virtual {v1, v5}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_9
    iget-object v6, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    invoke-static {v5}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v7

    invoke-virtual {v6, v7}, Llyiahf/vczjk/xo8;->OooO00o(Llyiahf/vczjk/jqa;)Z

    move-result v6

    if-nez v6, :cond_a

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    new-instance v8, Ljava/lang/StringBuilder;

    const-string v9, "Starting work for "

    invoke-direct {v8, v9}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v9, v5, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-virtual {v8, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v6, v7, v8}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v6, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v5}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v5

    invoke-virtual {v6, v5}, Llyiahf/vczjk/xo8;->OooOOO(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/xj3;->OooOoO:Llyiahf/vczjk/zr9;

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zr9;->OooO0O0(Llyiahf/vczjk/g29;)V

    iget-object v6, p0, Llyiahf/vczjk/xj3;->OooOo00:Llyiahf/vczjk/bp8;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v7, Llyiahf/vczjk/oOO0;

    const/4 v8, 0x0

    const/16 v9, 0x11

    invoke-direct {v7, v6, v5, v9, v8}, Llyiahf/vczjk/oOO0;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iget-object v5, v6, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/rqa;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/rqa;->OooO00o(Ljava/lang/Runnable;)V

    :cond_a
    :goto_2
    add-int/lit8 v4, v4, 0x1

    goto/16 :goto_0

    :goto_3
    :try_start_1
    monitor-exit v6
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_b
    iget-object p1, p0, Llyiahf/vczjk/xj3;->OooOOo0:Ljava/lang/Object;

    monitor-enter p1

    :try_start_2
    invoke-virtual {v0}, Ljava/util/HashSet;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_d

    const-string v2, ","

    invoke-static {v2, v1}, Landroid/text/TextUtils;->join(Ljava/lang/CharSequence;Ljava/lang/Iterable;)Ljava/lang/String;

    move-result-object v1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    const-string v5, "Starting tracking for "

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v3, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_c
    :goto_4
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_d

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ara;

    invoke-static {v1}, Llyiahf/vczjk/br6;->OooOOoo(Llyiahf/vczjk/ara;)Llyiahf/vczjk/jqa;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/xj3;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v3, v2}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_c

    iget-object v3, p0, Llyiahf/vczjk/xj3;->OooOo:Llyiahf/vczjk/aqa;

    iget-object v4, p0, Llyiahf/vczjk/xj3;->OooOoO0:Llyiahf/vczjk/rqa;

    iget-object v4, v4, Llyiahf/vczjk/rqa;->OooO0O0:Llyiahf/vczjk/qr1;

    invoke-static {v3, v1, v4, p0}, Llyiahf/vczjk/cqa;->OooO00o(Llyiahf/vczjk/aqa;Llyiahf/vczjk/ara;Llyiahf/vczjk/qr1;Llyiahf/vczjk/pa6;)Llyiahf/vczjk/r09;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/xj3;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v3, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_4

    :catchall_1
    move-exception v0

    goto :goto_5

    :cond_d
    monitor-exit p1

    return-void

    :goto_5
    monitor-exit p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw v0
.end method

.method public final OooO0Oo(Ljava/lang/String;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0o:Ljava/lang/Boolean;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOO0:Landroid/content/Context;

    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOo0:Llyiahf/vczjk/wh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/m77;->OooO00o(Landroid/content/Context;Llyiahf/vczjk/wh1;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0o:Ljava/lang/Boolean;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0o:Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    sget-object v1, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    if-nez v0, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object p1

    const-string v0, "Ignoring schedule request in non-main process"

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/o55;->OooOOO0(Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/xj3;->OooOOOo:Z

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOoo:Llyiahf/vczjk/n77;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/n77;->OooO00o(Llyiahf/vczjk/gs2;)V

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/xj3;->OooOOOo:Z

    :cond_2
    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Cancelling work ID "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOOO:Llyiahf/vczjk/i52;

    if-eqz v0, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/i52;->OooO0Oo:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Runnable;

    if-eqz v1, :cond_3

    iget-object v0, v0, Llyiahf/vczjk/i52;->OooO0O0:Llyiahf/vczjk/sw7;

    iget-object v0, v0, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/os/Handler;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xo8;->OooOO0o(Ljava/lang/String;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/g29;

    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOoO:Llyiahf/vczjk/zr9;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zr9;->OooO00o(Llyiahf/vczjk/g29;)V

    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOo00:Llyiahf/vczjk/bp8;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 v2, -0x200

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/bp8;->OooO00o(Llyiahf/vczjk/g29;I)V

    goto :goto_0

    :cond_4
    return-void
.end method

.method public final OooO0o0(Llyiahf/vczjk/jqa;Z)V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOo:Llyiahf/vczjk/xo8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xo8;->OooOOO0(Llyiahf/vczjk/jqa;)Llyiahf/vczjk/g29;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOoO:Llyiahf/vczjk/zr9;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zr9;->OooO00o(Llyiahf/vczjk/g29;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOOo0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/xj3;->OooOOO:Ljava/util/HashMap;

    invoke-virtual {v1, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/v74;

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    if-eqz v1, :cond_1

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/xj3;->OooOoOO:Ljava/lang/String;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Stopping tracking for "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-interface {v1, v0}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_1
    if-nez p2, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/xj3;->OooOOo0:Ljava/lang/Object;

    monitor-enter p2

    :try_start_1
    iget-object v0, p0, Llyiahf/vczjk/xj3;->OooOo0O:Ljava/util/HashMap;

    invoke-virtual {v0, p1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    monitor-exit p2

    return-void

    :catchall_0
    move-exception p1

    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :cond_2
    return-void

    :catchall_1
    move-exception p1

    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1
.end method
