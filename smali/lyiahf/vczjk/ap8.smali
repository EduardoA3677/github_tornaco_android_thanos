.class public final synthetic Llyiahf/vczjk/ap8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cp8;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cp8;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ap8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ap8;->OooOOO:Llyiahf/vczjk/cp8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ap8;->OooOOO0:I

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ap8;->OooOOO:Llyiahf/vczjk/cp8;

    if-eqz p1, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/cp8;->OooO00o:Llyiahf/vczjk/yo8;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/String;

    invoke-static {p1, v0}, Llyiahf/vczjk/yo8;->OooO0o0(Llyiahf/vczjk/yo8;[Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/cp8;->OooO0o()V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ap8;->OooOOO:Llyiahf/vczjk/cp8;

    if-eqz p1, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/cp8;->OooO00o:Llyiahf/vczjk/yo8;

    invoke-static {p1}, Llyiahf/vczjk/yo8;->OooO0o(Llyiahf/vczjk/yo8;)V

    goto :goto_1

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/cp8;->OooO0o()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
