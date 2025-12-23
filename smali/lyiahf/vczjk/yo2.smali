.class public final Llyiahf/vczjk/yo2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $target:J

.field final synthetic this$0:Llyiahf/vczjk/dp2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dp2;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yo2;->this$0:Llyiahf/vczjk/dp2;

    iput-wide p2, p0, Llyiahf/vczjk/yo2;->$target:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/co2;

    iget-object v0, p0, Llyiahf/vczjk/yo2;->this$0:Llyiahf/vczjk/dp2;

    iget-wide v1, p0, Llyiahf/vczjk/yo2;->$target:J

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_1

    const/4 v3, 0x1

    if-eq p1, v3, :cond_2

    const/4 v3, 0x2

    if-ne p1, v3, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/dp2;->Oooo000:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0OO:Llyiahf/vczjk/ls0;

    if-eqz p1, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/ls0;->OooO0O0:Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_2

    new-instance v0, Llyiahf/vczjk/b24;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v1, p1, Llyiahf/vczjk/b24;->OooO00o:J

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    iget-object p1, v0, Llyiahf/vczjk/dp2;->OooOooo:Llyiahf/vczjk/ep2;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0OO:Llyiahf/vczjk/ls0;

    if-eqz p1, :cond_2

    iget-object p1, p1, Llyiahf/vczjk/ls0;->OooO0O0:Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_2

    new-instance v0, Llyiahf/vczjk/b24;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v1, p1, Llyiahf/vczjk/b24;->OooO00o:J

    :cond_2
    :goto_0
    new-instance p1, Llyiahf/vczjk/b24;

    invoke-direct {p1, v1, v2}, Llyiahf/vczjk/b24;-><init>(J)V

    return-object p1
.end method
