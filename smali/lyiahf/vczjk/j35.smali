.class public final Llyiahf/vczjk/j35;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $globalRotation:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/j35;->$globalRotation:Llyiahf/vczjk/gi;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/j35;

    iget-object v0, p0, Llyiahf/vczjk/j35;->$globalRotation:Llyiahf/vczjk/gi;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/j35;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/j35;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/j35;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/j35;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/j35;->label:I

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

    iget-object v1, p0, Llyiahf/vczjk/j35;->$globalRotation:Llyiahf/vczjk/gi;

    move p1, v2

    new-instance v2, Ljava/lang/Float;

    const/high16 v3, 0x43b40000    # 360.0f

    invoke-direct {v2, v3}, Ljava/lang/Float;-><init>(F)V

    sget-object v3, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    const/16 v4, 0x123a

    const/4 v5, 0x0

    const/4 v6, 0x2

    invoke-static {v4, v5, v3, v6}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/gq7;->OooOOO0:Llyiahf/vczjk/gq7;

    const/4 v4, 0x4

    invoke-static {v3, v4}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v3

    iput p1, p0, Llyiahf/vczjk/j35;->label:I

    const/4 v4, 0x0

    const/16 v6, 0xc

    move-object v5, p0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
