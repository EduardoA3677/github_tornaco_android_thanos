.class public final Llyiahf/vczjk/ha0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $text:Llyiahf/vczjk/an;

.field final synthetic $textScope:Llyiahf/vczjk/zm9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zm9;Llyiahf/vczjk/an;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ha0;->$textScope:Llyiahf/vczjk/zm9;

    iput-object p2, p0, Llyiahf/vczjk/ha0;->$text:Llyiahf/vczjk/an;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/ha0;->$textScope:Llyiahf/vczjk/zm9;

    if-eqz v0, :cond_3

    iget-object v1, v0, Llyiahf/vczjk/zm9;->OooO0OO:Llyiahf/vczjk/tw8;

    invoke-virtual {v1}, Llyiahf/vczjk/tw8;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/zm9;->OooO0O0:Llyiahf/vczjk/an;

    goto :goto_1

    :cond_0
    new-instance v2, Llyiahf/vczjk/nh9;

    iget-object v3, v0, Llyiahf/vczjk/zm9;->OooO0O0:Llyiahf/vczjk/an;

    invoke-direct {v2, v3}, Llyiahf/vczjk/nh9;-><init>(Llyiahf/vczjk/an;)V

    invoke-virtual {v1}, Llyiahf/vczjk/tw8;->size()I

    move-result v3

    const/4 v4, 0x0

    :goto_0
    if-ge v4, v3, :cond_1

    invoke-virtual {v1, v4}, Llyiahf/vczjk/tw8;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-interface {v5, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    iget-object v1, v2, Llyiahf/vczjk/nh9;->OooO0O0:Llyiahf/vczjk/an;

    :goto_1
    iput-object v1, v0, Llyiahf/vczjk/zm9;->OooO0O0:Llyiahf/vczjk/an;

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    return-object v1

    :cond_3
    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/ha0;->$text:Llyiahf/vczjk/an;

    return-object v0
.end method
