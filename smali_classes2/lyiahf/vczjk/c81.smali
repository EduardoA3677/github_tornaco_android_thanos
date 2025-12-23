.class public final Llyiahf/vczjk/c81;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/t81;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/t81;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c81;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/c81;->OooOOO:Llyiahf/vczjk/t81;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/c81;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/e71;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/c81;->OooOOO:Llyiahf/vczjk/t81;

    invoke-virtual {p1}, Llyiahf/vczjk/e71;->OooO00o()Z

    move-result v1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/t81;->OooOO0O(Llyiahf/vczjk/e71;Z)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/e71;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/c81;->OooOOO:Llyiahf/vczjk/t81;

    invoke-virtual {p1}, Llyiahf/vczjk/e71;->OooO00o()Z

    move-result v1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/t81;->OooOO0O(Llyiahf/vczjk/e71;Z)Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
