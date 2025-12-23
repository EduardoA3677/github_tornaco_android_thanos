.class public final synthetic Llyiahf/vczjk/g28;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/h48;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/h48;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/g28;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g28;->OooOOO:Llyiahf/vczjk/h48;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/h48;I)V
    .locals 0

    const/4 p2, 0x1

    iput p2, p0, Llyiahf/vczjk/g28;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/g28;->OooOOO:Llyiahf/vczjk/h48;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/g28;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/g28;->OooOOO:Llyiahf/vczjk/h48;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/ok6;->OooO(Llyiahf/vczjk/h48;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/z8a;

    check-cast p2, Ljava/lang/String;

    const-string p1, "id"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Ltornaco/apps/thanox/core/proto/common/FreezeMethod;->valueOf(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/FreezeMethod;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/g28;->OooOOO:Llyiahf/vczjk/h48;

    const-string v0, "method"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/t38;

    const/4 v2, 0x0

    invoke-direct {v1, p2, p1, v2}, Llyiahf/vczjk/t38;-><init>(Llyiahf/vczjk/h48;Ltornaco/apps/thanox/core/proto/common/FreezeMethod;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v0, v2, v2, v1, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
