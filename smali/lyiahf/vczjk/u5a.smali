.class public abstract Llyiahf/vczjk/u5a;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/kh6;

.field public static final OooO0O0:Llyiahf/vczjk/i95;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const-string v0, "TypefaceCompat static init"

    invoke-static {v0}, Llyiahf/vczjk/ll6;->OooOOo0(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1d

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/z5a;

    invoke-direct {v0}, Llyiahf/vczjk/kh6;-><init>()V

    sput-object v0, Llyiahf/vczjk/u5a;->OooO00o:Llyiahf/vczjk/kh6;

    goto :goto_0

    :cond_0
    const/16 v1, 0x1c

    if-lt v0, v1, :cond_1

    new-instance v0, Llyiahf/vczjk/y5a;

    invoke-direct {v0}, Llyiahf/vczjk/x5a;-><init>()V

    sput-object v0, Llyiahf/vczjk/u5a;->OooO00o:Llyiahf/vczjk/kh6;

    goto :goto_0

    :cond_1
    const/16 v1, 0x1a

    if-lt v0, v1, :cond_2

    new-instance v0, Llyiahf/vczjk/x5a;

    invoke-direct {v0}, Llyiahf/vczjk/x5a;-><init>()V

    sput-object v0, Llyiahf/vczjk/u5a;->OooO00o:Llyiahf/vczjk/kh6;

    goto :goto_0

    :cond_2
    sget-object v0, Llyiahf/vczjk/w5a;->OooO0Oo:Ljava/lang/reflect/Method;

    if-nez v0, :cond_3

    const-string v1, "TypefaceCompatApi24Impl"

    const-string v2, "Unable to collect necessary private methods.Fallback to legacy implementation."

    invoke-static {v1, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    :cond_3
    if-eqz v0, :cond_4

    new-instance v0, Llyiahf/vczjk/w5a;

    invoke-direct {v0}, Llyiahf/vczjk/kh6;-><init>()V

    sput-object v0, Llyiahf/vczjk/u5a;->OooO00o:Llyiahf/vczjk/kh6;

    goto :goto_0

    :cond_4
    new-instance v0, Llyiahf/vczjk/v5a;

    invoke-direct {v0}, Llyiahf/vczjk/kh6;-><init>()V

    sput-object v0, Llyiahf/vczjk/u5a;->OooO00o:Llyiahf/vczjk/kh6;

    :goto_0
    new-instance v0, Llyiahf/vczjk/i95;

    const/16 v1, 0x10

    invoke-direct {v0, v1}, Llyiahf/vczjk/i95;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/u5a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-static {}, Landroid/os/Trace;->endSection()V

    return-void
.end method

.method public static OooO00o(Landroid/content/Context;Llyiahf/vczjk/ua3;Landroid/content/res/Resources;ILjava/lang/String;IILlyiahf/vczjk/cl6;Z)Landroid/graphics/Typeface;
    .locals 16

    move-object/from16 v2, p0

    move-object/from16 v0, p1

    move/from16 v4, p6

    move-object/from16 v1, p7

    const/4 v3, 0x7

    const/16 v5, 0x17

    const/4 v6, 0x1

    const/4 v7, 0x0

    instance-of v8, v0, Llyiahf/vczjk/xa3;

    const/4 v9, -0x3

    if-eqz v8, :cond_10

    check-cast v0, Llyiahf/vczjk/xa3;

    iget-object v8, v0, Llyiahf/vczjk/xa3;->OooO0o0:Ljava/lang/String;

    if-eqz v8, :cond_1

    invoke-virtual {v8}, Ljava/lang/String;->isEmpty()Z

    move-result v11

    if-eqz v11, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v8, v7}, Landroid/graphics/Typeface;->create(Ljava/lang/String;I)Landroid/graphics/Typeface;

    move-result-object v8

    sget-object v11, Landroid/graphics/Typeface;->DEFAULT:Landroid/graphics/Typeface;

    invoke-static {v11, v7}, Landroid/graphics/Typeface;->create(Landroid/graphics/Typeface;I)Landroid/graphics/Typeface;

    move-result-object v11

    if-eqz v8, :cond_1

    invoke-virtual {v8, v11}, Landroid/graphics/Typeface;->equals(Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v8, 0x0

    :goto_1
    if-eqz v8, :cond_3

    if-eqz v1, :cond_2

    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-direct {v0, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance v2, Llyiahf/vczjk/tm4;

    invoke-direct {v2, v5, v1, v8}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    :cond_2
    return-object v8

    :cond_3
    if-eqz p8, :cond_5

    iget v5, v0, Llyiahf/vczjk/xa3;->OooO0Oo:I

    if-nez v5, :cond_4

    :goto_2
    move v5, v6

    goto :goto_3

    :cond_4
    move v5, v7

    goto :goto_3

    :cond_5
    if-nez v1, :cond_4

    goto :goto_2

    :goto_3
    const/4 v8, -0x1

    if-eqz p8, :cond_6

    iget v11, v0, Llyiahf/vczjk/xa3;->OooO0OO:I

    goto :goto_4

    :cond_6
    move v11, v8

    :goto_4
    new-instance v12, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v13

    invoke-direct {v12, v13}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance v13, Llyiahf/vczjk/bh6;

    invoke-direct {v13}, Ljava/lang/Object;-><init>()V

    iput-object v1, v13, Llyiahf/vczjk/bh6;->OooOOO0:Ljava/lang/Object;

    iget-object v1, v0, Llyiahf/vczjk/xa3;->OooO0O0:Llyiahf/vczjk/na3;

    if-eqz v1, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/xa3;->OooO00o:Llyiahf/vczjk/na3;

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    const/4 v14, 0x2

    invoke-direct {v1, v14}, Ljava/util/ArrayList;-><init>(I)V

    move v15, v7

    :goto_5
    if-ge v15, v14, :cond_7

    aget-object v10, v0, v15

    invoke-static {v10}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v1, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/2addr v15, v6

    goto :goto_5

    :cond_7
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    goto :goto_6

    :cond_8
    iget-object v0, v0, Llyiahf/vczjk/xa3;->OooO00o:Llyiahf/vczjk/na3;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, v6}, Ljava/util/ArrayList;-><init>(I)V

    aget-object v0, v0, v7

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    :goto_6
    new-instance v10, Llyiahf/vczjk/n62;

    new-instance v1, Llyiahf/vczjk/wd;

    const/4 v14, 0x4

    invoke-direct {v1, v12, v14}, Llyiahf/vczjk/wd;-><init>(Ljava/lang/Object;I)V

    const/16 v12, 0x8

    invoke-direct {v10, v12, v13, v1, v7}, Llyiahf/vczjk/n62;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    if-eqz v5, :cond_c

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v5

    if-gt v5, v6, :cond_b

    invoke-interface {v0, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/na3;

    sget-object v5, Llyiahf/vczjk/ta3;->OooO00o:Llyiahf/vczjk/i95;

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v5

    new-instance v12, Ljava/util/ArrayList;

    invoke-direct {v12, v6}, Ljava/util/ArrayList;-><init>(I)V

    aget-object v5, v5, v7

    invoke-static {v5}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v12, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {v12}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/ta3;->OooO00o(ILjava/util/List;)Ljava/lang/String;

    move-result-object v5

    sget-object v12, Llyiahf/vczjk/ta3;->OooO00o:Llyiahf/vczjk/i95;

    invoke-virtual {v12, v5}, Llyiahf/vczjk/i95;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Landroid/graphics/Typeface;

    if-eqz v12, :cond_9

    new-instance v0, Llyiahf/vczjk/js2;

    invoke-direct {v0, v3, v13, v12, v7}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    move-object v10, v12

    goto/16 :goto_b

    :cond_9
    if-ne v11, v8, :cond_a

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, v6}, Ljava/util/ArrayList;-><init>(I)V

    aget-object v0, v0, v7

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    invoke-static {v5, v2, v0, v4}, Llyiahf/vczjk/ta3;->OooO0O0(Ljava/lang/String;Landroid/content/Context;Ljava/util/List;I)Llyiahf/vczjk/sa3;

    move-result-object v0

    invoke-virtual {v10, v0}, Llyiahf/vczjk/n62;->o0000Ooo(Llyiahf/vczjk/sa3;)V

    iget-object v10, v0, Llyiahf/vczjk/sa3;->OooO00o:Landroid/graphics/Typeface;

    goto/16 :goto_b

    :cond_a
    move-object v3, v0

    new-instance v0, Llyiahf/vczjk/qa3;

    move-object v1, v5

    const/4 v5, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/qa3;-><init>(Ljava/lang/String;Landroid/content/Context;Ljava/lang/Object;II)V

    :try_start_0
    sget-object v1, Llyiahf/vczjk/ta3;->OooO0O0:Ljava/util/concurrent/ThreadPoolExecutor;

    invoke-interface {v1, v0}, Ljava/util/concurrent/ExecutorService;->submit(Ljava/util/concurrent/Callable;)Ljava/util/concurrent/Future;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/InterruptedException; {:try_start_0 .. :try_end_0} :catch_3

    int-to-long v1, v11

    :try_start_1
    sget-object v3, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    invoke-interface {v0, v1, v2, v3}, Ljava/util/concurrent/Future;->get(JLjava/util/concurrent/TimeUnit;)Ljava/lang/Object;

    move-result-object v0
    :try_end_1
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0
    .catch Ljava/util/concurrent/TimeoutException; {:try_start_1 .. :try_end_1} :catch_2

    :try_start_2
    check-cast v0, Llyiahf/vczjk/sa3;

    invoke-virtual {v10, v0}, Llyiahf/vczjk/n62;->o0000Ooo(Llyiahf/vczjk/sa3;)V

    iget-object v10, v0, Llyiahf/vczjk/sa3;->OooO00o:Landroid/graphics/Typeface;

    goto/16 :goto_b

    :catch_0
    move-exception v0

    goto :goto_7

    :catch_1
    move-exception v0

    goto :goto_8

    :catch_2
    new-instance v0, Ljava/lang/InterruptedException;

    const-string v1, "timeout"

    invoke-direct {v0, v1}, Ljava/lang/InterruptedException;-><init>(Ljava/lang/String;)V

    throw v0

    :goto_7
    throw v0

    :goto_8
    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1
    :try_end_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_3

    :catch_3
    new-instance v0, Llyiahf/vczjk/ro0;

    iget-object v1, v10, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/bh6;

    invoke-direct {v0, v9, v7, v1}, Llyiahf/vczjk/ro0;-><init>(IILjava/lang/Object;)V

    iget-object v1, v10, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wd;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    :goto_9
    const/4 v10, 0x0

    goto/16 :goto_b

    :cond_b
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Fallbacks with blocking fetches are not supported for performance reasons"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_c
    invoke-static {v4, v0}, Llyiahf/vczjk/ta3;->OooO00o(ILjava/util/List;)Ljava/lang/String;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/ta3;->OooO00o:Llyiahf/vczjk/i95;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/i95;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/graphics/Typeface;

    if-eqz v5, :cond_d

    new-instance v0, Llyiahf/vczjk/js2;

    invoke-direct {v0, v3, v13, v5, v7}, Llyiahf/vczjk/js2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/wd;->execute(Ljava/lang/Runnable;)V

    move-object v10, v5

    goto :goto_b

    :cond_d
    new-instance v1, Llyiahf/vczjk/ra3;

    invoke-direct {v1, v10, v7}, Llyiahf/vczjk/ra3;-><init>(Ljava/lang/Object;I)V

    sget-object v3, Llyiahf/vczjk/ta3;->OooO0OO:Ljava/lang/Object;

    monitor-enter v3

    :try_start_3
    sget-object v5, Llyiahf/vczjk/ta3;->OooO0Oo:Llyiahf/vczjk/ao8;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/ao8;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Ljava/util/ArrayList;

    if-eqz v7, :cond_e

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    monitor-exit v3

    goto :goto_9

    :catchall_0
    move-exception v0

    goto :goto_c

    :cond_e
    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v5, v2, v7}, Llyiahf/vczjk/ao8;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    move-object v3, v0

    new-instance v0, Llyiahf/vczjk/qa3;

    const/4 v5, 0x1

    move-object v1, v2

    move-object/from16 v2, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/qa3;-><init>(Ljava/lang/String;Landroid/content/Context;Ljava/lang/Object;II)V

    sget-object v2, Llyiahf/vczjk/ta3;->OooO0O0:Ljava/util/concurrent/ThreadPoolExecutor;

    new-instance v3, Llyiahf/vczjk/ra3;

    invoke-direct {v3, v1, v6}, Llyiahf/vczjk/ra3;-><init>(Ljava/lang/Object;I)V

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v1

    if-nez v1, :cond_f

    new-instance v1, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v5

    invoke-direct {v1, v5}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    goto :goto_a

    :cond_f
    new-instance v1, Landroid/os/Handler;

    invoke-direct {v1}, Landroid/os/Handler;-><init>()V

    :goto_a
    new-instance v5, Llyiahf/vczjk/uj1;

    invoke-direct {v5}, Llyiahf/vczjk/uj1;-><init>()V

    iput-object v0, v5, Llyiahf/vczjk/uj1;->OooOOO:Ljava/lang/Object;

    iput-object v3, v5, Llyiahf/vczjk/uj1;->OooOOOO:Ljava/lang/Object;

    iput-object v1, v5, Llyiahf/vczjk/uj1;->OooOOOo:Ljava/lang/Object;

    invoke-virtual {v2, v5}, Ljava/util/concurrent/ThreadPoolExecutor;->execute(Ljava/lang/Runnable;)V

    goto :goto_9

    :goto_b
    move-object/from16 v6, p2

    goto :goto_d

    :goto_c
    :try_start_4
    monitor-exit v3
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    throw v0

    :cond_10
    sget-object v3, Llyiahf/vczjk/u5a;->OooO00o:Llyiahf/vczjk/kh6;

    check-cast v0, Llyiahf/vczjk/va3;

    move-object/from16 v6, p2

    invoke-virtual {v3, v2, v0, v6, v4}, Llyiahf/vczjk/kh6;->OooOOO(Landroid/content/Context;Llyiahf/vczjk/va3;Landroid/content/res/Resources;I)Landroid/graphics/Typeface;

    move-result-object v10

    if-eqz v1, :cond_12

    if-eqz v10, :cond_11

    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-direct {v0, v2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance v2, Llyiahf/vczjk/tm4;

    invoke-direct {v2, v5, v1, v10}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_d

    :cond_11
    invoke-virtual {v1, v9}, Llyiahf/vczjk/cl6;->OooO0oO(I)V

    :cond_12
    :goto_d
    if-eqz v10, :cond_13

    sget-object v0, Llyiahf/vczjk/u5a;->OooO0O0:Llyiahf/vczjk/i95;

    invoke-static/range {p2 .. p6}, Llyiahf/vczjk/u5a;->OooO0O0(Landroid/content/res/Resources;ILjava/lang/String;II)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, v10}, Llyiahf/vczjk/i95;->OooO0OO(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_13
    return-object v10
.end method

.method public static OooO0O0(Landroid/content/res/Resources;ILjava/lang/String;II)Ljava/lang/String;
    .locals 1

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0, p1}, Landroid/content/res/Resources;->getResourcePackageName(I)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p0, 0x2d

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
