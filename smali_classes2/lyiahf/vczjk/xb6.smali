.class public final synthetic Llyiahf/vczjk/xb6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/nc6;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nc6;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/xb6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/xb6;->OooOOO:Llyiahf/vczjk/nc6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/xb6;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/cc6;

    packed-switch v0, :pswitch_data_0

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xb6;->OooOOO:Llyiahf/vczjk/nc6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nc6;->OooO0o(Llyiahf/vczjk/cc6;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xb6;->OooOOO:Llyiahf/vczjk/nc6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nc6;->OooO0o(Llyiahf/vczjk/cc6;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/xb6;->OooOOO:Llyiahf/vczjk/nc6;

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/kc6;

    const/4 v4, 0x0

    invoke-direct {v3, v0, p1, v1, v4}, Llyiahf/vczjk/kc6;-><init>(Llyiahf/vczjk/nc6;Llyiahf/vczjk/cc6;Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v2, v4, v4, v3, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
