.class public final Llyiahf/vczjk/m39;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/n39;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/n39;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/m39;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/m39;->OooOOO:Llyiahf/vczjk/n39;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/m39;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/m39;->OooOOO:Llyiahf/vczjk/n39;

    iget-boolean v1, v0, Llyiahf/vczjk/n39;->OooO0OO:Z

    if-eqz v1, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/n39;->OooO0O0:Llyiahf/vczjk/h82;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->Oooo(Llyiahf/vczjk/oo0o0Oo;)Llyiahf/vczjk/ua7;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->OoooO00(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :goto_0
    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/m39;->OooOOO:Llyiahf/vczjk/n39;

    iget-object v1, v0, Llyiahf/vczjk/n39;->OooO0O0:Llyiahf/vczjk/h82;

    invoke-static {v1}, Llyiahf/vczjk/dn8;->OoooO00(Llyiahf/vczjk/oo0o0Oo;)Llyiahf/vczjk/ho8;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/n39;->OooO0O0:Llyiahf/vczjk/h82;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->OoooO0(Llyiahf/vczjk/oo0o0Oo;)Llyiahf/vczjk/ho8;

    move-result-object v0

    filled-new-array {v1, v0}, [Llyiahf/vczjk/ho8;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
