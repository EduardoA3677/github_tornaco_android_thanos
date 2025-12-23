.class public final Llyiahf/vczjk/c7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oe3;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/c7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/c7;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/c7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/wd8;

    iget-object v1, p0, Llyiahf/vczjk/c7;->OooOOO:Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/wd8;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    check-cast p1, Llyiahf/vczjk/nb9;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/nb9;->o00000OO(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/nr3;

    iget-object v1, p0, Llyiahf/vczjk/c7;->OooOOO:Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/nr3;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/u34;->OooOo00(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/vn1;

    const/4 v1, 0x0

    iget-object v2, p0, Llyiahf/vczjk/c7;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/vn1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/u34;->OooO0o0(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p1, p2, :cond_2

    goto :goto_2

    :cond_2
    move-object p1, v0

    :goto_2
    if-ne p1, p2, :cond_3

    move-object v0, p1

    :cond_3
    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/b7;

    iget-object v1, p0, Llyiahf/vczjk/c7;->OooOOO:Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/b7;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)V

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/u34;->OooOo00(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_4

    goto :goto_3

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_3
    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
