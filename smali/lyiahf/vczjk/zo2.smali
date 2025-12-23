.class public final Llyiahf/vczjk/zo2;
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

    iput-object p1, p0, Llyiahf/vczjk/zo2;->this$0:Llyiahf/vczjk/dp2;

    iput-wide p2, p0, Llyiahf/vczjk/zo2;->$target:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/co2;

    iget-object v0, p0, Llyiahf/vczjk/zo2;->this$0:Llyiahf/vczjk/dp2;

    iget-wide v2, p0, Llyiahf/vczjk/zo2;->$target:J

    iget-object v1, v0, Llyiahf/vczjk/dp2;->Oooo0O0:Llyiahf/vczjk/o4;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/dp2;->o00000OO()Llyiahf/vczjk/o4;

    move-result-object v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    iget-object v1, v0, Llyiahf/vczjk/dp2;->Oooo0O0:Llyiahf/vczjk/o4;

    invoke-virtual {v0}, Llyiahf/vczjk/dp2;->o00000OO()Llyiahf/vczjk/o4;

    move-result-object v4

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_0

    :cond_2
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_4

    const/4 v1, 0x1

    if-eq p1, v1, :cond_4

    const/4 v1, 0x2

    if-ne p1, v1, :cond_3

    iget-object p1, v0, Llyiahf/vczjk/dp2;->Oooo000:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0OO:Llyiahf/vczjk/ls0;

    if-eqz p1, :cond_4

    new-instance v1, Llyiahf/vczjk/b24;

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/b24;-><init>(J)V

    iget-object p1, p1, Llyiahf/vczjk/ls0;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {p1, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v4, p1, Llyiahf/vczjk/b24;->OooO00o:J

    invoke-virtual {v0}, Llyiahf/vczjk/dp2;->o00000OO()Llyiahf/vczjk/o4;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object v6, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/o4;->OooO00o(JJLlyiahf/vczjk/yn4;)J

    move-result-wide v7

    iget-object v1, v0, Llyiahf/vczjk/dp2;->Oooo0O0:Llyiahf/vczjk/o4;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/o4;->OooO00o(JJLlyiahf/vczjk/yn4;)J

    move-result-wide v0

    invoke-static {v7, v8, v0, v1}, Llyiahf/vczjk/u14;->OooO0OO(JJ)J

    move-result-wide v0

    goto :goto_1

    :cond_3
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_4
    :goto_0
    const-wide/16 v0, 0x0

    :goto_1
    new-instance p1, Llyiahf/vczjk/u14;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/u14;-><init>(J)V

    return-object p1
.end method
