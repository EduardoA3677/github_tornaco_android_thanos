.class public final Llyiahf/vczjk/h80;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $durationMillis:I

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i80;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i80;ILlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h80;->this$0:Llyiahf/vczjk/i80;

    iput p2, p0, Llyiahf/vczjk/h80;->$durationMillis:I

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/h80;

    iget-object v0, p0, Llyiahf/vczjk/h80;->this$0:Llyiahf/vczjk/i80;

    iget v1, p0, Llyiahf/vczjk/h80;->$durationMillis:I

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/h80;-><init>(Llyiahf/vczjk/i80;ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/h80;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/h80;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/h80;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/h80;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/h80;->this$0:Llyiahf/vczjk/i80;

    iget-object p1, p1, Llyiahf/vczjk/i80;->Oooo0O0:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v3

    const/high16 v1, 0x3f800000    # 1.0f

    add-float/2addr v1, p1

    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, p1}, Ljava/lang/Float;-><init>(F)V

    new-instance p1, Ljava/lang/Float;

    invoke-direct {p1, v1}, Ljava/lang/Float;-><init>(F)V

    invoke-virtual {v3, v4, p1}, Llyiahf/vczjk/gi;->OooO0oO(Ljava/lang/Float;Ljava/lang/Float;)V

    new-instance v4, Ljava/lang/Float;

    invoke-direct {v4, v1}, Ljava/lang/Float;-><init>(F)V

    iget p1, p0, Llyiahf/vczjk/h80;->$durationMillis:I

    sget-object v1, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    const/4 v5, 0x0

    const/4 v6, 0x2

    invoke-static {p1, v5, v1, v6}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/gq7;->OooOOO0:Llyiahf/vczjk/gq7;

    const/4 v1, 0x4

    invoke-static {p1, v1}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v5

    iget-object p1, p0, Llyiahf/vczjk/h80;->this$0:Llyiahf/vczjk/i80;

    new-instance v6, Llyiahf/vczjk/o000OO;

    const/16 v1, 0xd

    invoke-direct {v6, p1, v1}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/h80;->label:I

    const/4 v8, 0x4

    move-object v7, p0

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
