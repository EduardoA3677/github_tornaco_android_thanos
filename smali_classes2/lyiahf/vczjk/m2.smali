.class public final Llyiahf/vczjk/m2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $priv:Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

.field final synthetic $profile:Lgithub/tornaco/android/thanos/core/secure/field/Fields;

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Lgithub/tornaco/android/thanos/core/secure/field/Fields;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/m2;->$priv:Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

    iput-object p2, p0, Llyiahf/vczjk/m2;->$profile:Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/m2;

    iget-object v1, p0, Llyiahf/vczjk/m2;->$priv:Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

    iget-object v2, p0, Llyiahf/vczjk/m2;->$profile:Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/m2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Lgithub/tornaco/android/thanos/core/secure/field/Fields;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/m2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ljava/util/List;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/m2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/m2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/m2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/m2;->label:I

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/m2;->L$0:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/m2;->$priv:Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

    iget-object v1, p0, Llyiahf/vczjk/m2;->$profile:Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xw;

    iget-object v2, v2, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getId()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v2, v3}, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;->selectFieldsProfileForPackage(Ljava/lang/String;Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
