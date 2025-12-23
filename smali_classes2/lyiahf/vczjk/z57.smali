.class public final synthetic Llyiahf/vczjk/z57;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/k77;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/k77;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/z57;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/z57;->OooOOO:Llyiahf/vczjk/k77;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/z57;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Lgithub/tornaco/android/thanos/core/net/TrafficStatsState;

    iget-object v1, p0, Llyiahf/vczjk/z57;->OooOOO:Llyiahf/vczjk/k77;

    iget-object v1, v1, Llyiahf/vczjk/k77;->OooO0o0:Landroid/content/Context;

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/net/TrafficStatsState;-><init>(Landroid/content/Context;)V

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/z57;->OooOOO:Llyiahf/vczjk/k77;

    iget-object v0, v0, Llyiahf/vczjk/k77;->OooO0o0:Landroid/content/Context;

    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v0

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/z57;->OooOOO:Llyiahf/vczjk/k77;

    const-wide/16 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/k77;->OooOO0o(J)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/z57;->OooOOO:Llyiahf/vczjk/k77;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/b77;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/b77;-><init>(Llyiahf/vczjk/k77;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {v1, v3, v3, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
