.class public final Llyiahf/vczjk/yf2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $velocity:J

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/zf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zf2;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yf2;->this$0:Llyiahf/vczjk/zf2;

    iput-wide p2, p0, Llyiahf/vczjk/yf2;->$velocity:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/yf2;

    iget-object v1, p0, Llyiahf/vczjk/yf2;->this$0:Llyiahf/vczjk/zf2;

    iget-wide v2, p0, Llyiahf/vczjk/yf2;->$velocity:J

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/yf2;-><init>(Llyiahf/vczjk/zf2;JLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/yf2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/yf2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/yf2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yf2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/yf2;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/yf2;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object v1, p0, Llyiahf/vczjk/yf2;->this$0:Llyiahf/vczjk/zf2;

    iget-object v3, v1, Llyiahf/vczjk/zf2;->Oooo0oo:Llyiahf/vczjk/bf3;

    iget-wide v4, p0, Llyiahf/vczjk/yf2;->$velocity:J

    iget-boolean v1, v1, Llyiahf/vczjk/zf2;->Oooo:Z

    if-eqz v1, :cond_2

    const/high16 v1, -0x40800000    # -1.0f

    :goto_0
    invoke-static {v1, v4, v5}, Llyiahf/vczjk/fea;->OooO0o(FJ)J

    move-result-wide v4

    goto :goto_1

    :cond_2
    const/high16 v1, 0x3f800000    # 1.0f

    goto :goto_0

    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/yf2;->this$0:Llyiahf/vczjk/zf2;

    iget-object v1, v1, Llyiahf/vczjk/zf2;->Oooo0o0:Llyiahf/vczjk/nf6;

    sget-object v6, Llyiahf/vczjk/uf2;->OooO00o:Llyiahf/vczjk/rf2;

    sget-object v6, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v1, v6, :cond_3

    invoke-static {v4, v5}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result v1

    goto :goto_2

    :cond_3
    invoke-static {v4, v5}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result v1

    :goto_2
    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, v1}, Ljava/lang/Float;-><init>(F)V

    iput v2, p0, Llyiahf/vczjk/yf2;->label:I

    invoke-interface {v3, p1, v4, p0}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
