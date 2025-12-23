.class public final Llyiahf/vczjk/vn2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $cacheKey:Lcoil/memory/MemoryCache$Key;

.field final synthetic $chain:Llyiahf/vczjk/t24;

.field final synthetic $eventListener:Llyiahf/vczjk/jr2;

.field final synthetic $mappedData:Ljava/lang/Object;

.field final synthetic $options:Llyiahf/vczjk/hf6;

.field final synthetic $request:Llyiahf/vczjk/kv3;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/wn2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wn2;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hf6;Llyiahf/vczjk/jr2;Lcoil/memory/MemoryCache$Key;Llyiahf/vczjk/t24;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vn2;->this$0:Llyiahf/vczjk/wn2;

    iput-object p2, p0, Llyiahf/vczjk/vn2;->$request:Llyiahf/vczjk/kv3;

    iput-object p3, p0, Llyiahf/vczjk/vn2;->$mappedData:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/vn2;->$options:Llyiahf/vczjk/hf6;

    iput-object p5, p0, Llyiahf/vczjk/vn2;->$eventListener:Llyiahf/vczjk/jr2;

    iput-object p6, p0, Llyiahf/vczjk/vn2;->$cacheKey:Lcoil/memory/MemoryCache$Key;

    iput-object p7, p0, Llyiahf/vczjk/vn2;->$chain:Llyiahf/vczjk/t24;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p8}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 9

    new-instance v0, Llyiahf/vczjk/vn2;

    iget-object v1, p0, Llyiahf/vczjk/vn2;->this$0:Llyiahf/vczjk/wn2;

    iget-object v2, p0, Llyiahf/vczjk/vn2;->$request:Llyiahf/vczjk/kv3;

    iget-object v3, p0, Llyiahf/vczjk/vn2;->$mappedData:Ljava/lang/Object;

    iget-object v4, p0, Llyiahf/vczjk/vn2;->$options:Llyiahf/vczjk/hf6;

    iget-object v5, p0, Llyiahf/vczjk/vn2;->$eventListener:Llyiahf/vczjk/jr2;

    iget-object v6, p0, Llyiahf/vczjk/vn2;->$cacheKey:Lcoil/memory/MemoryCache$Key;

    iget-object v7, p0, Llyiahf/vczjk/vn2;->$chain:Llyiahf/vczjk/t24;

    move-object v8, p2

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/vn2;-><init>(Llyiahf/vczjk/wn2;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hf6;Llyiahf/vczjk/jr2;Lcoil/memory/MemoryCache$Key;Llyiahf/vczjk/t24;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/vn2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vn2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vn2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v5, p0

    sget-object v6, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, v5, Llyiahf/vczjk/vn2;->label:I

    const/4 v7, 0x1

    if-eqz v0, :cond_1

    if-ne v0, v7, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v0, p1

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v0, v5, Llyiahf/vczjk/vn2;->this$0:Llyiahf/vczjk/wn2;

    iget-object v1, v5, Llyiahf/vczjk/vn2;->$request:Llyiahf/vczjk/kv3;

    iget-object v2, v5, Llyiahf/vczjk/vn2;->$mappedData:Ljava/lang/Object;

    iget-object v3, v5, Llyiahf/vczjk/vn2;->$options:Llyiahf/vczjk/hf6;

    iget-object v4, v5, Llyiahf/vczjk/vn2;->$eventListener:Llyiahf/vczjk/jr2;

    iput v7, v5, Llyiahf/vczjk/vn2;->label:I

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/wn2;->OooO0O0(Llyiahf/vczjk/wn2;Llyiahf/vczjk/kv3;Ljava/lang/Object;Llyiahf/vczjk/hf6;Llyiahf/vczjk/jr2;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v6, :cond_2

    return-object v6

    :cond_2
    :goto_0
    check-cast v0, Llyiahf/vczjk/pn2;

    iget-object v1, v5, Llyiahf/vczjk/vn2;->this$0:Llyiahf/vczjk/wn2;

    iget-object v1, v1, Llyiahf/vczjk/wn2;->OooO0O0:Llyiahf/vczjk/gd9;

    monitor-enter v1

    :try_start_0
    iget-object v2, v1, Llyiahf/vczjk/gd9;->OooOOO0:Ljava/lang/ref/WeakReference;

    invoke-virtual {v2}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ii7;

    if-eqz v2, :cond_3

    iget-object v3, v1, Llyiahf/vczjk/gd9;->OooOOO:Landroid/content/Context;

    if-nez v3, :cond_4

    iget-object v2, v2, Llyiahf/vczjk/ii7;->OooO00o:Landroid/content/Context;

    iput-object v2, v1, Llyiahf/vczjk/gd9;->OooOOO:Landroid/content/Context;

    invoke-virtual {v2, v1}, Landroid/content/Context;->registerComponentCallbacks(Landroid/content/ComponentCallbacks;)V

    goto :goto_1

    :catchall_0
    move-exception v0

    goto/16 :goto_7

    :cond_3
    invoke-virtual {v1}, Llyiahf/vczjk/gd9;->OooO0O0()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_4
    :goto_1
    monitor-exit v1

    iget-object v1, v5, Llyiahf/vczjk/vn2;->this$0:Llyiahf/vczjk/wn2;

    iget-object v1, v1, Llyiahf/vczjk/wn2;->OooO0Oo:Llyiahf/vczjk/sw7;

    iget-object v2, v5, Llyiahf/vczjk/vn2;->$cacheKey:Lcoil/memory/MemoryCache$Key;

    iget-object v3, v5, Llyiahf/vczjk/vn2;->$request:Llyiahf/vczjk/kv3;

    iget-object v3, v3, Llyiahf/vczjk/kv3;->OooOOO:Llyiahf/vczjk/vm0;

    invoke-virtual {v3}, Llyiahf/vczjk/vm0;->OooO0O0()Z

    move-result v3

    const/4 v4, 0x0

    const/4 v6, 0x0

    if-nez v3, :cond_6

    :cond_5
    :goto_2
    move v1, v4

    goto :goto_4

    :cond_6
    iget-object v1, v1, Llyiahf/vczjk/sw7;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ii7;

    iget-object v1, v1, Llyiahf/vczjk/ii7;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/mi7;

    if-eqz v1, :cond_5

    if-nez v2, :cond_7

    goto :goto_2

    :cond_7
    iget-object v3, v0, Llyiahf/vczjk/pn2;->OooO00o:Landroid/graphics/drawable/Drawable;

    instance-of v8, v3, Landroid/graphics/drawable/BitmapDrawable;

    if-eqz v8, :cond_8

    check-cast v3, Landroid/graphics/drawable/BitmapDrawable;

    goto :goto_3

    :cond_8
    move-object v3, v6

    :goto_3
    if-eqz v3, :cond_5

    invoke-virtual {v3}, Landroid/graphics/drawable/BitmapDrawable;->getBitmap()Landroid/graphics/Bitmap;

    move-result-object v3

    if-nez v3, :cond_9

    goto :goto_2

    :cond_9
    new-instance v8, Ljava/util/LinkedHashMap;

    invoke-direct {v8}, Ljava/util/LinkedHashMap;-><init>()V

    iget-boolean v9, v0, Llyiahf/vczjk/pn2;->OooO0O0:Z

    invoke-static {v9}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v9

    const-string v10, "coil#is_sampled"

    invoke-interface {v8, v10, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v9, v0, Llyiahf/vczjk/pn2;->OooO0Oo:Ljava/lang/String;

    if-eqz v9, :cond_a

    const-string v10, "coil#disk_cache_key"

    invoke-interface {v8, v10, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_a
    iget-object v9, v2, Lcoil/memory/MemoryCache$Key;->OooOOO:Ljava/util/Map;

    invoke-static {v9}, Llyiahf/vczjk/ng0;->Ooooo0o(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v9

    new-instance v10, Lcoil/memory/MemoryCache$Key;

    iget-object v2, v2, Lcoil/memory/MemoryCache$Key;->OooOOO0:Ljava/lang/String;

    invoke-direct {v10, v2, v9}, Lcoil/memory/MemoryCache$Key;-><init>(Ljava/lang/String;Ljava/util/Map;)V

    invoke-static {v8}, Llyiahf/vczjk/ng0;->Ooooo0o(Ljava/util/Map;)Ljava/util/Map;

    move-result-object v2

    iget-object v1, v1, Llyiahf/vczjk/mi7;->OooO00o:Llyiahf/vczjk/k79;

    invoke-interface {v1, v10, v3, v2}, Llyiahf/vczjk/k79;->OooO0O0(Lcoil/memory/MemoryCache$Key;Landroid/graphics/Bitmap;Ljava/util/Map;)V

    move v1, v7

    :goto_4
    iget-object v9, v0, Llyiahf/vczjk/pn2;->OooO00o:Landroid/graphics/drawable/Drawable;

    iget-object v10, v5, Llyiahf/vczjk/vn2;->$request:Llyiahf/vczjk/kv3;

    iget-object v11, v0, Llyiahf/vczjk/pn2;->OooO0OO:Llyiahf/vczjk/zx1;

    iget-object v2, v5, Llyiahf/vczjk/vn2;->$cacheKey:Lcoil/memory/MemoryCache$Key;

    if-eqz v1, :cond_b

    move-object v12, v2

    goto :goto_5

    :cond_b
    move-object v12, v6

    :goto_5
    iget-object v13, v0, Llyiahf/vczjk/pn2;->OooO0Oo:Ljava/lang/String;

    iget-boolean v14, v0, Llyiahf/vczjk/pn2;->OooO0O0:Z

    iget-object v0, v5, Llyiahf/vczjk/vn2;->$chain:Llyiahf/vczjk/t24;

    sget-object v1, Llyiahf/vczjk/OooOOO0;->OooO00o:Landroid/graphics/Bitmap$Config;

    instance-of v1, v0, Llyiahf/vczjk/li7;

    if-eqz v1, :cond_c

    check-cast v0, Llyiahf/vczjk/li7;

    iget-boolean v0, v0, Llyiahf/vczjk/li7;->OooO0oO:Z

    if-eqz v0, :cond_c

    move v15, v7

    goto :goto_6

    :cond_c
    move v15, v4

    :goto_6
    new-instance v8, Llyiahf/vczjk/l99;

    invoke-direct/range {v8 .. v15}, Llyiahf/vczjk/l99;-><init>(Landroid/graphics/drawable/Drawable;Llyiahf/vczjk/kv3;Llyiahf/vczjk/zx1;Lcoil/memory/MemoryCache$Key;Ljava/lang/String;ZZ)V

    return-object v8

    :goto_7
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method
