.class public final Llyiahf/vczjk/ec6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Llyiahf/vczjk/sc9;

.field public final OooO0OO:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ec6;->OooO00o:Landroid/content/Context;

    new-instance p1, Llyiahf/vczjk/fz3;

    const/16 v0, 0x10

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ec6;->OooO0O0:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/p35;

    const/16 v0, 0xb

    invoke-direct {p1, v0}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ec6;->OooO0OO:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p1, Llyiahf/vczjk/dc6;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/dc6;

    iget v1, v0, Llyiahf/vczjk/dc6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/dc6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/dc6;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/dc6;-><init>(Llyiahf/vczjk/ec6;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/dc6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/dc6;->label:I

    iget-object v3, p0, Llyiahf/vczjk/ec6;->OooO0O0:Llyiahf/vczjk/sc9;

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v5, :cond_2

    if-ne v2, v4, :cond_1

    iget-object v2, v0, Llyiahf/vczjk/dc6;->L$1:Ljava/lang/Object;

    check-cast v2, Ljava/util/Iterator;

    iget-object v5, v0, Llyiahf/vczjk/dc6;->L$0:Ljava/lang/Object;

    check-cast v5, Ljava/util/Collection;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_5

    :catchall_0
    move-exception p1

    goto/16 :goto_6

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fc6;

    iput v5, v0, Llyiahf/vczjk/dc6;->label:I

    invoke-interface {p1, v0}, Llyiahf/vczjk/fc6;->OooO00o(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_4

    goto :goto_4

    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/Iterable;

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_5
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_6

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Lgithub/tornaco/thanos/android/module/profile/repo/GithubFileInfo;

    invoke-virtual {v6}, Lgithub/tornaco/thanos/android/module/profile/repo/GithubFileInfo;->getType()Ljava/lang/String;

    move-result-object v6

    const-string v7, "file"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_5

    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_6
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v2

    move-object v5, p1

    :cond_7
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_a

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/repo/GithubFileInfo;

    :try_start_1
    invoke-virtual {v3}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/fc6;

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/repo/GithubFileInfo;->getName()Ljava/lang/String;

    move-result-object p1

    iput-object v5, v0, Llyiahf/vczjk/dc6;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/dc6;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/dc6;->label:I

    invoke-interface {v6, p1, v0}, Llyiahf/vczjk/fc6;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_8

    :goto_4
    return-object v1

    :cond_8
    :goto_5
    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/repo/GithubFileContent;

    invoke-virtual {p1}, Lgithub/tornaco/thanos/android/module/profile/repo/GithubFileContent;->getContent()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/os9;->OooOo0(Ljava/lang/String;)[B

    move-result-object p1

    iget-object v6, p0, Llyiahf/vczjk/ec6;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v6}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nk3;

    new-instance v7, Ljava/lang/String;

    sget-object v8, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    invoke-direct {v7, p1, v8}, Ljava/lang/String;-><init>([BLjava/nio/charset/Charset;)V

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;

    invoke-virtual {v6, p1, v7}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_7

    :goto_6
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_7
    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v6

    if-nez v6, :cond_9

    goto :goto_8

    :cond_9
    const-string p1, "getProfileFileContent error"

    invoke-static {p1, v6}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    const/4 p1, 0x0

    :goto_8
    check-cast p1, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;

    if-eqz p1, :cond_7

    invoke-interface {v5, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_a
    check-cast v5, Ljava/util/List;

    return-object v5
.end method
