.class public final synthetic Llyiahf/vczjk/hw6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/function/Predicate;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/gu6;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/gu6;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/hw6;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/hw6;->OooO0O0:Llyiahf/vczjk/gu6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final test(Ljava/lang/Object;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/hw6;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/hw6;->OooO0O0:Llyiahf/vczjk/gu6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gu6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/hw6;->OooO0O0:Llyiahf/vczjk/gu6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gu6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/hw6;->OooO0O0:Llyiahf/vczjk/gu6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/gu6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
