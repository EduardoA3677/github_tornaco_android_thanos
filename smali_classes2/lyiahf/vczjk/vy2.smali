.class public final Llyiahf/vczjk/vy2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Llyiahf/vczjk/uy2;

.field public OooO00o:Llyiahf/vczjk/v25;

.field public OooO0O0:Z

.field public OooO0OO:Z

.field public OooO0Oo:Z

.field public final OooO0o:Ljava/util/concurrent/ThreadPoolExecutor;

.field public OooO0o0:Z

.field public volatile OooO0oO:Llyiahf/vczjk/w00;

.field public volatile OooO0oo:Llyiahf/vczjk/w00;

.field public final synthetic OooOO0:Llyiahf/vczjk/wy2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wy2;Landroidx/fragment/app/FragmentActivity;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vy2;->OooOO0:Llyiahf/vczjk/wy2;

    sget-object p1, Llyiahf/vczjk/w00;->OooOo00:Ljava/util/concurrent/ThreadPoolExecutor;

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/vy2;->OooO0O0:Z

    iput-boolean v0, p0, Llyiahf/vczjk/vy2;->OooO0OO:Z

    const/4 v1, 0x1

    iput-boolean v1, p0, Llyiahf/vczjk/vy2;->OooO0Oo:Z

    iput-boolean v0, p0, Llyiahf/vczjk/vy2;->OooO0o0:Z

    invoke-virtual {p2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    iput-object p1, p0, Llyiahf/vczjk/vy2;->OooO0o:Ljava/util/concurrent/ThreadPoolExecutor;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    if-eqz v0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/vy2;->OooO0O0:Z

    const/4 v1, 0x1

    if-nez v0, :cond_0

    iput-boolean v1, p0, Llyiahf/vczjk/vy2;->OooO0o0:Z

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oo:Llyiahf/vczjk/w00;

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iput-object v2, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    return-void

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    iget-object v3, v0, Llyiahf/vczjk/w00;->OooOOOo:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v3, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    iget-object v0, v0, Llyiahf/vczjk/w00;->OooOOO:Llyiahf/vczjk/e95;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/util/concurrent/FutureTask;->cancel(Z)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    iput-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oo:Llyiahf/vczjk/w00;

    :cond_2
    iput-object v2, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    :cond_3
    return-void
.end method

.method public final OooO0O0()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oo:Llyiahf/vczjk/w00;

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/vy2;->OooO0oO:Llyiahf/vczjk/w00;

    iget-object v1, p0, Llyiahf/vczjk/vy2;->OooO0o:Ljava/util/concurrent/ThreadPoolExecutor;

    iget v2, v0, Llyiahf/vczjk/w00;->OooOOOO:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eq v2, v4, :cond_2

    iget v0, v0, Llyiahf/vczjk/w00;->OooOOOO:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    if-eq v0, v4, :cond_1

    if-eq v0, v3, :cond_0

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "We should never reach this state"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot execute task: the task has already been executed (a task can be executed only once)"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot execute task: the task is already running."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    iput v3, v0, Llyiahf/vczjk/w00;->OooOOOO:I

    iget-object v2, v0, Llyiahf/vczjk/w00;->OooOOO0:Llyiahf/vczjk/bl5;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/w00;->OooOOO:Llyiahf/vczjk/e95;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    :cond_3
    return-void
.end method

.method public final OooO0OO()Llyiahf/vczjk/qx8;
    .locals 16

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/vy2;->OooOO0:Llyiahf/vczjk/wy2;

    iget-object v2, v1, Llyiahf/vczjk/o000OOo0;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Ljava/io/File;

    invoke-virtual {v2}, Ljava/io/File;->listFiles()[Ljava/io/File;

    move-result-object v2

    const/4 v3, 0x0

    if-nez v2, :cond_0

    move v4, v3

    goto :goto_0

    :cond_0
    array-length v4, v2

    :goto_0
    new-instance v5, Llyiahf/vczjk/qx8;

    new-instance v6, Llyiahf/vczjk/ty2;

    new-instance v7, Llyiahf/vczjk/ly2;

    invoke-direct {v7, v1}, Llyiahf/vczjk/ly2;-><init>(Llyiahf/vczjk/o000OOo0;)V

    invoke-direct {v6, v0, v7}, Llyiahf/vczjk/ty2;-><init>(Llyiahf/vczjk/vy2;Llyiahf/vczjk/ly2;)V

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    const-class v7, Ljava/io/File;

    invoke-static {v7, v4}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, [Ljava/lang/Object;

    iput-object v4, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    iput-object v6, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    iput v3, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    iget-object v4, v5, Llyiahf/vczjk/qx8;->OooO0OO:Llyiahf/vczjk/ox8;

    if-nez v4, :cond_1

    new-instance v4, Llyiahf/vczjk/ox8;

    invoke-direct {v4, v6}, Llyiahf/vczjk/ox8;-><init>(Llyiahf/vczjk/px8;)V

    iput-object v4, v5, Llyiahf/vczjk/qx8;->OooO0OO:Llyiahf/vczjk/ox8;

    :cond_1
    iget-object v4, v5, Llyiahf/vczjk/qx8;->OooO0OO:Llyiahf/vczjk/ox8;

    iput-object v4, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    if-eqz v2, :cond_14

    array-length v4, v2

    move v6, v3

    :goto_1
    if-ge v6, v4, :cond_14

    aget-object v8, v2, v6

    invoke-virtual {v8}, Ljava/io/File;->isHidden()Z

    move-result v9

    if-eqz v9, :cond_2

    goto/16 :goto_e

    :cond_2
    invoke-virtual {v8}, Ljava/io/File;->isDirectory()Z

    move-result v9

    const/4 v10, 0x2

    if-nez v9, :cond_3

    iget v9, v1, Llyiahf/vczjk/o000OOo0;->OooOOOO:I

    if-eqz v9, :cond_3

    if-eq v9, v10, :cond_3

    const/4 v11, 0x3

    if-ne v9, v11, :cond_12

    iget-boolean v9, v1, Llyiahf/vczjk/o000OOo0;->OooOOoo:Z

    if-eqz v9, :cond_12

    :cond_3
    iget-object v9, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    iget v11, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    move v12, v3

    :goto_2
    const/4 v13, -0x1

    if-ge v12, v11, :cond_d

    add-int v14, v12, v11

    div-int/2addr v14, v10

    aget-object v15, v9, v14

    iget-object v10, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v10, v15, v8}, Llyiahf/vczjk/px8;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    move-result v10

    if-gez v10, :cond_4

    add-int/lit8 v12, v14, 0x1

    goto :goto_a

    :cond_4
    if-nez v10, :cond_c

    iget-object v9, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v9, v15, v8}, Llyiahf/vczjk/px8;->OooO0OO(Ljava/lang/Object;Ljava/io/File;)Z

    move-result v9

    if-eqz v9, :cond_5

    goto :goto_9

    :cond_5
    add-int/lit8 v9, v14, -0x1

    :goto_3
    if-lt v9, v12, :cond_8

    iget-object v10, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    aget-object v10, v10, v9

    iget-object v15, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v15, v10, v8}, Llyiahf/vczjk/px8;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    move-result v15

    if-eqz v15, :cond_6

    goto :goto_5

    :cond_6
    iget-object v15, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v15, v10, v8}, Llyiahf/vczjk/px8;->OooO0OO(Ljava/lang/Object;Ljava/io/File;)Z

    move-result v10

    if-eqz v10, :cond_7

    :goto_4
    move v12, v9

    goto :goto_8

    :cond_7
    add-int/lit8 v9, v9, -0x1

    goto :goto_3

    :cond_8
    :goto_5
    add-int/lit8 v9, v14, 0x1

    :goto_6
    if-ge v9, v11, :cond_b

    iget-object v10, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    aget-object v10, v10, v9

    iget-object v12, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v12, v10, v8}, Llyiahf/vczjk/px8;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    move-result v12

    if-eqz v12, :cond_9

    goto :goto_7

    :cond_9
    iget-object v12, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v12, v10, v8}, Llyiahf/vczjk/px8;->OooO0OO(Ljava/lang/Object;Ljava/io/File;)Z

    move-result v10

    if-eqz v10, :cond_a

    goto :goto_4

    :cond_a
    add-int/lit8 v9, v9, 0x1

    goto :goto_6

    :cond_b
    :goto_7
    move v12, v13

    :goto_8
    if-ne v12, v13, :cond_d

    :goto_9
    move v12, v14

    goto :goto_b

    :cond_c
    move v11, v14

    :goto_a
    const/4 v10, 0x2

    goto :goto_2

    :cond_d
    :goto_b
    const/4 v9, 0x1

    if-ne v12, v13, :cond_e

    move v12, v3

    goto :goto_c

    :cond_e
    iget v10, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    if-ge v12, v10, :cond_10

    iget-object v10, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    aget-object v10, v10, v12

    iget-object v11, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v11, v10, v8}, Llyiahf/vczjk/px8;->OooO0OO(Ljava/lang/Object;Ljava/io/File;)Z

    move-result v11

    if-eqz v11, :cond_10

    iget-object v11, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v11, v10, v8}, Llyiahf/vczjk/px8;->OooO00o(Ljava/lang/Object;Ljava/io/File;)Z

    move-result v11

    if-eqz v11, :cond_f

    iget-object v9, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    aput-object v8, v9, v12

    goto :goto_e

    :cond_f
    iget-object v11, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    aput-object v8, v11, v12

    iget-object v11, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-virtual {v11, v10, v8}, Llyiahf/vczjk/px8;->OooO0Oo(Ljava/lang/Object;Ljava/io/File;)Ljava/lang/Object;

    move-result-object v8

    invoke-virtual {v11, v12, v9, v8}, Llyiahf/vczjk/px8;->OooOO0o(IILjava/lang/Object;)V

    goto :goto_e

    :cond_10
    :goto_c
    iget v10, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    if-gt v12, v10, :cond_13

    iget-object v11, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    array-length v13, v11

    if-ne v10, v13, :cond_11

    array-length v10, v11

    add-int/lit8 v10, v10, 0xa

    invoke-static {v7, v10}, Ljava/lang/reflect/Array;->newInstance(Ljava/lang/Class;I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, [Ljava/lang/Object;

    iget-object v11, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    invoke-static {v11, v3, v10, v3, v12}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    aput-object v8, v10, v12

    iget-object v8, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    add-int/lit8 v11, v12, 0x1

    iget v13, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    sub-int/2addr v13, v12

    invoke-static {v8, v12, v10, v11, v13}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    iput-object v10, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    goto :goto_d

    :cond_11
    add-int/lit8 v13, v12, 0x1

    sub-int/2addr v10, v12

    invoke-static {v11, v12, v11, v13, v10}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    iget-object v10, v5, Llyiahf/vczjk/qx8;->OooO00o:[Ljava/lang/Object;

    aput-object v8, v10, v12

    :goto_d
    iget v8, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    add-int/2addr v8, v9

    iput v8, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    iget-object v8, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    invoke-interface {v8, v12, v9}, Llyiahf/vczjk/q15;->OooO0oO(II)V

    :cond_12
    :goto_e
    add-int/lit8 v6, v6, 0x1

    goto/16 :goto_1

    :cond_13
    new-instance v1, Ljava/lang/IndexOutOfBoundsException;

    const-string v2, "cannot add item to "

    const-string v3, " because size is "

    invoke-static {v12, v2, v3}, Llyiahf/vczjk/ii5;->OooOOO(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    iget v3, v5, Llyiahf/vczjk/qx8;->OooO0Oo:I

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-direct {v1, v2}, Ljava/lang/IndexOutOfBoundsException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_14
    iget-object v1, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    instance-of v2, v1, Llyiahf/vczjk/ox8;

    if-eqz v2, :cond_15

    check-cast v1, Llyiahf/vczjk/ox8;

    iget-object v1, v1, Llyiahf/vczjk/ox8;->OooOOO:Llyiahf/vczjk/na0;

    invoke-virtual {v1}, Llyiahf/vczjk/na0;->OooO00o()V

    :cond_15
    iget-object v1, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    iget-object v2, v5, Llyiahf/vczjk/qx8;->OooO0OO:Llyiahf/vczjk/ox8;

    if-ne v1, v2, :cond_16

    iget-object v1, v2, Llyiahf/vczjk/ox8;->OooOOO0:Llyiahf/vczjk/px8;

    iput-object v1, v5, Llyiahf/vczjk/qx8;->OooO0O0:Llyiahf/vczjk/px8;

    :cond_16
    return-object v5
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const/16 v1, 0x40

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V

    invoke-static {v0, p0}, Llyiahf/vczjk/tg0;->OooOo00(Ljava/lang/StringBuilder;Ljava/lang/Object;)V

    const-string v1, " id="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v1, "}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
