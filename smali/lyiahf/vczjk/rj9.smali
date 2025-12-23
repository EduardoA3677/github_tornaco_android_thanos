.class public final Llyiahf/vczjk/rj9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $scrollerPosition:Llyiahf/vczjk/vj9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vj9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/rj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/rj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    invoke-virtual {v0}, Llyiahf/vczjk/vj9;->OooO00o()F

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/rj9;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iget-object v1, v1, Llyiahf/vczjk/vj9;->OooO0O0:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    invoke-virtual {v1}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v1

    cmpg-float v0, v0, v1

    if-gez v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    return-object v0
.end method
