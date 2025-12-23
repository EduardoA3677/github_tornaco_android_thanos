.class public final Llyiahf/vczjk/x20;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/i40;

.field public final synthetic OooOOO0:Ljava/util/List;

.field public final synthetic OooOOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public final synthetic OooOOOo:Llyiahf/vczjk/p29;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/i40;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/p29;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/x20;->OooOOO0:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/x20;->OooOOO:Llyiahf/vczjk/i40;

    iput-object p3, p0, Llyiahf/vczjk/x20;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object p4, p0, Llyiahf/vczjk/x20;->OooOOOo:Llyiahf/vczjk/p29;

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/x20;->OooOOOo:Llyiahf/vczjk/p29;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    const/4 v1, 0x3

    iget-object v2, p0, Llyiahf/vczjk/x20;->OooOOO0:Ljava/util/List;

    if-nez v0, :cond_1

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v0

    if-ge v0, v1, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v0}, Llyiahf/vczjk/im4;->OooO00o()V

    goto :goto_1

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/x20;->OooOOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-interface {v2, v0}, Ljava/util/List;->contains(Ljava/lang/Object;)Z

    move-result v2

    xor-int/lit8 v2, v2, 0x1

    iget-object v3, p0, Llyiahf/vczjk/x20;->OooOOO:Llyiahf/vczjk/i40;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v3}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/h40;

    const/4 v6, 0x0

    invoke-direct {v5, v0, v2, v3, v6}, Llyiahf/vczjk/h40;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V

    invoke-static {v4, v6, v6, v5, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_1
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
