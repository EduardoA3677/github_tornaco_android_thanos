.class public final Llyiahf/vczjk/b81;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/t81;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/t81;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/b81;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/b81;->OooOOO:Llyiahf/vczjk/t81;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/b81;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/e71;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    const-string v0, "componentModel"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/b81;->OooOOO:Llyiahf/vczjk/t81;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/t81;->OooO(Llyiahf/vczjk/e71;Z)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/e71;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    const-string v0, "componentModel"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/b81;->OooOOO:Llyiahf/vczjk/t81;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/t81;->OooO(Llyiahf/vczjk/e71;Z)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
