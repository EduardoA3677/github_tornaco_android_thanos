.class public final Llyiahf/vczjk/c41;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field synthetic J$0:J

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g41;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g41;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/c41;->this$0:Llyiahf/vczjk/g41;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/l37;

    check-cast p2, Llyiahf/vczjk/p86;

    iget-wide v0, p2, Llyiahf/vczjk/p86;->OooO00o:J

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance p2, Llyiahf/vczjk/c41;

    iget-object v2, p0, Llyiahf/vczjk/c41;->this$0:Llyiahf/vczjk/g41;

    invoke-direct {p2, v2, p3}, Llyiahf/vczjk/c41;-><init>(Llyiahf/vczjk/g41;Llyiahf/vczjk/yo1;)V

    iput-object p1, p2, Llyiahf/vczjk/c41;->L$0:Ljava/lang/Object;

    iput-wide v0, p2, Llyiahf/vczjk/c41;->J$0:J

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/c41;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/c41;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/c41;->L$0:Ljava/lang/Object;

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/l37;

    iget-wide v6, p0, Llyiahf/vczjk/c41;->J$0:J

    iget-object v9, p0, Llyiahf/vczjk/c41;->this$0:Llyiahf/vczjk/g41;

    iget-boolean p1, v9, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    if-eqz p1, :cond_3

    iput v3, p0, Llyiahf/vczjk/c41;->label:I

    iget-object v8, v9, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    if-eqz v8, :cond_2

    new-instance v4, Llyiahf/vczjk/o00000O;

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/o00000O;-><init>(Llyiahf/vczjk/l37;JLlyiahf/vczjk/rr5;Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/yo1;)V

    invoke-static {v4, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    return-object v2
.end method
