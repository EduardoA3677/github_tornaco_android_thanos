.class public final synthetic Llyiahf/vczjk/u77;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/g87;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/g87;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/u77;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/u77;->OooOOO:Llyiahf/vczjk/g87;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/u77;->OooOOO:Llyiahf/vczjk/g87;

    iget v1, p0, Llyiahf/vczjk/u77;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    iget-object v0, v0, Llyiahf/vczjk/g87;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    sget v1, Lgithub/tornaco/thanos/android/module/profile/example/ProfileExampleActivity;->OoooO0O:I

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/f87;

    const/4 v3, 0x0

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/f87;-><init>(Llyiahf/vczjk/g87;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {v1, v3, v3, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
