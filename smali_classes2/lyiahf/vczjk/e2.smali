.class public final synthetic Llyiahf/vczjk/e2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/e2;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/e2;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/e2;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;II)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/e2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/e2;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/e2;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    const/16 v0, 0x37

    const-string v1, "Canceled."

    const/4 v2, 0x0

    const/4 v3, 0x3

    const-string v4, "files"

    const/4 v5, 0x0

    const/16 v6, 0x31

    const/4 v7, 0x1

    iget-object v8, p0, Llyiahf/vczjk/e2;->OooOOO:Ljava/lang/Object;

    iget-object v9, p0, Llyiahf/vczjk/e2;->OooOOOO:Ljava/lang/Object;

    sget-object v10, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget v11, p0, Llyiahf/vczjk/e2;->OooOOO0:I

    packed-switch v11, :pswitch_data_0

    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast p2, Ljava/util/List;

    invoke-static {p2, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    invoke-static {p2}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jd2;

    if-eqz p1, :cond_5

    check-cast v9, Llyiahf/vczjk/i48;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object p2, v9, Llyiahf/vczjk/i48;->OooO0o0:Landroid/content/Context;

    invoke-static {p1, p2}, Llyiahf/vczjk/t51;->OoooO0(Llyiahf/vczjk/jd2;Landroid/content/Context;)Ljava/io/InputStream;

    move-result-object p1

    if-nez p1, :cond_0

    const-string p1, "Unable to open input stream."

    invoke-static {p2, p1, v7}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    goto/16 :goto_5

    :cond_0
    invoke-static {p2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v0

    :try_start_0
    new-instance v1, Ljava/io/InputStreamReader;

    sget-object v2, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-direct {v1, p1, v2}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    invoke-static {v1}, Llyiahf/vczjk/tn6;->OooOOOo(Ljava/io/Reader;)Ljava/lang/String;

    move-result-object v1

    sget-object v2, Lgithub/tornaco/android/thanos/core/util/GsonUtils;->GSON:Llyiahf/vczjk/nk3;

    new-instance v4, Lnow/fortuitous/thanos/sf/SFVM$parseJsonToPackages$1;

    invoke-direct {v4}, Lnow/fortuitous/thanos/sf/SFVM$parseJsonToPackages$1;-><init>()V

    invoke-virtual {v4}, Lcom/google/gson/reflect/TypeToken;->getType()Ljava/lang/reflect/Type;

    move-result-object v4

    invoke-virtual {v2, v1, v4}, Llyiahf/vczjk/nk3;->OooO0Oo(Ljava/lang/String;Ljava/lang/reflect/Type;)Ljava/lang/Object;

    move-result-object v1

    const-string v2, "fromJson(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v1, Ljava/util/Set;

    check-cast v1, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_3

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->systemUserPkg(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v4

    invoke-virtual {v0, v4}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v6

    if-nez v6, :cond_2

    move-object v4, v5

    :cond_2
    if-eqz v4, :cond_1

    invoke-virtual {v2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_3
    invoke-static {v9}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/q28;

    invoke-direct {v1, v9, v2, v5}, Llyiahf/vczjk/q28;-><init>(Llyiahf/vczjk/i48;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v5, v5, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object v0, v10

    goto :goto_2

    :goto_1
    :try_start_1
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_2
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_4

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    const-string v2, "Unable to read file. "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {p2, v0, v7}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p2

    invoke-virtual {p2}, Landroid/widget/Toast;->show()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_3

    :catchall_1
    move-exception v0

    move-object p2, v0

    goto :goto_4

    :cond_4
    :goto_3
    invoke-interface {p1}, Ljava/io/Closeable;->close()V

    goto :goto_5

    :goto_4
    :try_start_2
    throw p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :catchall_2
    move-exception v0

    invoke-static {p1, p2}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0

    :cond_5
    check-cast v8, Landroid/content/Context;

    invoke-static {v8, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    :goto_5
    return-object v10

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/mt6;->OooO0Oo(Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Ltornaco/apps/thanox/running/detail/RunningAppStateDetails;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/ht6;->OooO0OO(Ltornaco/apps/thanox/running/detail/RunningAppStateDetails;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/rr2;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/cl6;->OooO00o(Llyiahf/vczjk/rr2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_3
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/t67;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/xt6;->OooO0O0(Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_4
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/s67;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/vt6;->OooO00o(Llyiahf/vczjk/s67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_5
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/a91;

    check-cast v9, Llyiahf/vczjk/a91;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/wr6;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_6
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/le3;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/ok6;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_7
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Ljava/util/List;

    check-cast v9, Llyiahf/vczjk/le3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/yi4;->OooOOO(Ljava/util/List;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_8
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/a91;

    check-cast v8, Llyiahf/vczjk/r58;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/nqa;->OooO(Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_9
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v6}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    check-cast v9, Llyiahf/vczjk/le3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/c6a;->OooOOOO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_a
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v6}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/a91;

    check-cast v8, Llyiahf/vczjk/w41;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/zsa;->OooO0OO(Llyiahf/vczjk/w41;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_b
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v6}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/a91;

    check-cast v8, Llyiahf/vczjk/le3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/zsa;->OooOOOo(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_c
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/tw8;

    check-cast v9, Ljava/util/List;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/qqa;->OooO0oO(Llyiahf/vczjk/tw8;Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_d
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/l1a;

    check-cast v8, Llyiahf/vczjk/p42;

    invoke-virtual {v8, v9, p1, p2}, Llyiahf/vczjk/p42;->OooO00o(Llyiahf/vczjk/l1a;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_e
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/zp8;

    check-cast v8, Llyiahf/vczjk/z32;

    invoke-virtual {v8, v9, p1, p2}, Llyiahf/vczjk/z32;->OooO00o(Llyiahf/vczjk/zp8;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_f
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/mx5;

    check-cast v8, Llyiahf/vczjk/z22;

    invoke-virtual {v8, v9, p1, p2}, Llyiahf/vczjk/z22;->OooO00o(Llyiahf/vczjk/mx5;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_10
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/ld9;

    check-cast v8, Llyiahf/vczjk/j12;

    invoke-virtual {v8, v9, p1, p2}, Llyiahf/vczjk/j12;->OooO00o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_11
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Ljava/util/List;

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/bua;->OooOO0o(Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_12
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Ljava/lang/String;

    check-cast v9, Llyiahf/vczjk/a91;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/os9;->OooOO0O(Ljava/lang/String;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_13
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    check-cast p2, Ljava/util/List;

    invoke-static {p2, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    invoke-static {p2}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/jd2;

    if-eqz p1, :cond_7

    check-cast v9, Llyiahf/vczjk/dj8;

    new-instance p2, Ljava/io/File;

    iget-object v0, v9, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    invoke-virtual {v0}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    move-result-object v1

    const-string v4, "restore_tmp"

    invoke-direct {p2, v1, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    :try_start_3
    new-instance v1, Ljava/io/File;

    const-string v4, "tem_restore_%s.zip"

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v11

    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v6

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v6

    invoke-static {v6, v7}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4, v6}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v4

    invoke-direct {v1, p2, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/sb;->OooOo0O(Ljava/io/File;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/t51;->OoooO0(Llyiahf/vczjk/jd2;Landroid/content/Context;)Ljava/io/InputStream;

    move-result-object v0

    if-nez v0, :cond_6

    invoke-static {v9}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/yi8;

    invoke-direct {v1, v9, p1, v5}, Llyiahf/vczjk/yi8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/jd2;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v5, v5, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_7

    :catchall_3
    move-exception v0

    move-object p1, v0

    goto :goto_8

    :catch_0
    move-exception v0

    move-object p1, v0

    goto :goto_6

    :cond_6
    invoke-virtual {v0}, Ljava/io/InputStream;->available()I

    move-result p1

    new-array p1, p1, [B

    invoke-virtual {v0, p1}, Ljava/io/InputStream;->read([B)I

    invoke-static {p1, v1}, Llyiahf/vczjk/sb;->OoooOo0([BLjava/io/File;)V

    const/high16 p1, 0x10000000

    invoke-static {v1, p1}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;

    move-result-object p1

    invoke-virtual {v9}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getBackupAgent()Lgithub/tornaco/android/thanos/core/backup/BackupAgent;

    move-result-object v0

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/backup/BackupAgent;->performRestore(Landroid/os/ParcelFileDescriptor;)V

    invoke-static {v9}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/zi8;

    invoke-direct {v0, v9, v5}, Llyiahf/vczjk/zi8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v5, v5, v0, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    goto :goto_7

    :goto_6
    :try_start_4
    const-string v0, "restore fail"

    new-array v1, v2, [Ljava/lang/Object;

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    invoke-static {v9}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/aj8;

    invoke-direct {v1, v9, p1, v5}, Llyiahf/vczjk/aj8;-><init>(Llyiahf/vczjk/dj8;Ljava/lang/Exception;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v5, v5, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    :goto_7
    invoke-static {p2}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->deleteDirQuiet(Ljava/io/File;)V

    goto :goto_9

    :goto_8
    invoke-static {p2}, Lgithub/tornaco/android/thanos/core/util/FileUtils;->deleteDirQuiet(Ljava/io/File;)V

    throw p1

    :cond_7
    check-cast v8, Landroid/content/Context;

    invoke-static {v8, v1, v2}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    move-result-object p1

    invoke-virtual {p1}, Landroid/widget/Toast;->show()V

    :goto_9
    return-object v10

    :pswitch_14
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    check-cast v9, Llyiahf/vczjk/kl5;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/zsa;->OooO00o(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_15
    check-cast p1, Llyiahf/vczjk/z8a;

    check-cast p2, Llyiahf/vczjk/mr1;

    const-string v0, "<unused var>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "element"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Llyiahf/vczjk/fl7;

    iget p1, v9, Llyiahf/vczjk/fl7;->element:I

    add-int/2addr v7, p1

    iput v7, v9, Llyiahf/vczjk/fl7;->element:I

    check-cast v8, [Llyiahf/vczjk/or1;

    aput-object p2, v8, p1

    return-object v10

    :pswitch_16
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x7

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Llyiahf/vczjk/qz0;

    check-cast v9, Llyiahf/vczjk/dq;

    invoke-virtual {v8, v9, p1, p2}, Llyiahf/vczjk/qz0;->OooO0O0(Llyiahf/vczjk/dq;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_17
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result v2

    check-cast p2, Ljava/lang/Float;

    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    move-result v3

    check-cast v8, Llyiahf/vczjk/qs5;

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/gp3;

    const/4 v1, 0x0

    const/4 v4, 0x0

    const/16 v5, 0x9

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/gp3;->OooO00o(Llyiahf/vczjk/gp3;FFFFI)Llyiahf/vczjk/gp3;

    move-result-object p1

    invoke-interface {v8, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oe3;

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p2

    invoke-interface {p1, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v10

    :pswitch_18
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget p2, Lnow/fortuitous/thanos/settings/BuildPropActivity;->Oooo00O:I

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Lnow/fortuitous/thanos/settings/BuildPropActivity;

    check-cast v9, Llyiahf/vczjk/xn6;

    invoke-virtual {v8, v9, p1, p2}, Lnow/fortuitous/thanos/settings/BuildPropActivity;->OooOo0O(Llyiahf/vczjk/xn6;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_19
    check-cast v8, Ljava/time/LocalTime;

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v6}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/cp7;->OooO00o(Ljava/time/LocalTime;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_1a
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v6}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    check-cast v9, Llyiahf/vczjk/le3;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/ye5;->OooO0OO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_1b
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    check-cast v8, Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;

    check-cast v9, Llyiahf/vczjk/e60;

    invoke-static {v8, v9, p1, p2}, Llyiahf/vczjk/qqa;->OooO0OO(Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;Llyiahf/vczjk/e60;Llyiahf/vczjk/rf1;I)V

    return-object v10

    :pswitch_1c
    check-cast p1, Llyiahf/vczjk/xw;

    check-cast p2, Ljava/lang/String;

    sget v0, Lnow/fortuitous/thanos/apps/AioAppListActivity;->OoooO:I

    const-string v0, "app"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "id"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p2}, Ljava/lang/String;->length()I

    move-result v1

    if-lez v1, :cond_8

    move-object v5, p2

    :cond_8
    check-cast v8, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

    invoke-virtual {v8, v0, v5}, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;->selectFieldsProfileForPackage(Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object p1

    const-string p2, "fromAppInfo(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v9, Lnow/fortuitous/thanos/apps/AioAppListActivity;

    invoke-static {v9, p1}, Llyiahf/vczjk/kta;->OooO00o(Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-object v10

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1c
        :pswitch_1b
        :pswitch_1a
        :pswitch_19
        :pswitch_18
        :pswitch_17
        :pswitch_16
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
