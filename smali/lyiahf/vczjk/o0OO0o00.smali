.class public final synthetic Llyiahf/vczjk/o0OO0o00;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;II)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/o0OO0o00;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0OO0o00;->OooOOO:Llyiahf/vczjk/ow6;

    iput p2, p0, Llyiahf/vczjk/o0OO0o00;->OooOOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/o0OO0o00;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/nw6;

    packed-switch v0, :pswitch_data_0

    iget v0, p0, Llyiahf/vczjk/o0OO0o00;->OooOOOO:I

    neg-int v0, v0

    iget-object v1, p0, Llyiahf/vczjk/o0OO0o00;->OooOOO:Llyiahf/vczjk/ow6;

    const/4 v2, 0x0

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget v0, p0, Llyiahf/vczjk/o0OO0o00;->OooOOOO:I

    neg-int v0, v0

    iget-object v1, p0, Llyiahf/vczjk/o0OO0o00;->OooOOO:Llyiahf/vczjk/ow6;

    const/4 v2, 0x0

    invoke-static {p1, v1, v2, v0}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
