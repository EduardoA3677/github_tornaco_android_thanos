.class public final synthetic Llyiahf/vczjk/f51;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/g51;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/g51;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/f51;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/f51;->OooOOO:Llyiahf/vczjk/g51;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public accept(Ljava/lang/Object;)V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/f51;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/wu;

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/f51;->OooOOO:Llyiahf/vczjk/g51;

    iget-object v0, v0, Llyiahf/vczjk/g51;->OooOOOO:Llyiahf/vczjk/oOO000o;

    iget-object p1, p1, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v1, 0x1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/oOO000o;->OooOo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Z)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/f51;->OooOOO:Llyiahf/vczjk/g51;

    iget-object v0, v0, Llyiahf/vczjk/g51;->OooOOOO:Llyiahf/vczjk/oOO000o;

    iget-object p1, p1, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v1, 0x0

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/oOO000o;->OooOo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Z)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public run()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/f51;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/f51;->OooOOO:Llyiahf/vczjk/g51;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/t41;->OooO0o(Z)V

    return-void

    :pswitch_0
    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/f51;->OooOOO:Llyiahf/vczjk/g51;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/t41;->OooO0o(Z)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
