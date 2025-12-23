.class public final Llyiahf/vczjk/k1a;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $activeNodeBeforeSearch:Llyiahf/vczjk/d93;

.field final synthetic $direction:I

.field final synthetic $focusTransactionManager:Llyiahf/vczjk/f93;

.field final synthetic $focusedItem:Llyiahf/vczjk/wj7;

.field final synthetic $generationBeforeSearch:I

.field final synthetic $onFound:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $this_generateAndSearchChildren:Llyiahf/vczjk/d93;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f93;Llyiahf/vczjk/d93;Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/k1a;->$generationBeforeSearch:I

    iput-object p1, p0, Llyiahf/vczjk/k1a;->$focusTransactionManager:Llyiahf/vczjk/f93;

    iput-object p2, p0, Llyiahf/vczjk/k1a;->$activeNodeBeforeSearch:Llyiahf/vczjk/d93;

    iput-object p3, p0, Llyiahf/vczjk/k1a;->$this_generateAndSearchChildren:Llyiahf/vczjk/d93;

    iput-object p4, p0, Llyiahf/vczjk/k1a;->$focusedItem:Llyiahf/vczjk/wj7;

    iput p5, p0, Llyiahf/vczjk/k1a;->$direction:I

    iput-object p6, p0, Llyiahf/vczjk/k1a;->$onFound:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/mb0;

    iget v0, p0, Llyiahf/vczjk/k1a;->$generationBeforeSearch:I

    iget-object v1, p0, Llyiahf/vczjk/k1a;->$focusTransactionManager:Llyiahf/vczjk/f93;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/k1a;->$activeNodeBeforeSearch:Llyiahf/vczjk/d93;

    iget-object v1, p0, Llyiahf/vczjk/k1a;->$this_generateAndSearchChildren:Llyiahf/vczjk/d93;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/r83;

    iget-object v1, v1, Llyiahf/vczjk/r83;->OooOO0o:Llyiahf/vczjk/d93;

    if-eq v0, v1, :cond_0

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/k1a;->$this_generateAndSearchChildren:Llyiahf/vczjk/d93;

    iget-object v1, p0, Llyiahf/vczjk/k1a;->$focusedItem:Llyiahf/vczjk/wj7;

    iget v2, p0, Llyiahf/vczjk/k1a;->$direction:I

    iget-object v3, p0, Llyiahf/vczjk/k1a;->$onFound:Llyiahf/vczjk/oe3;

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/tp6;->Oooo00O(Llyiahf/vczjk/d93;Llyiahf/vczjk/wj7;ILlyiahf/vczjk/oe3;)Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    if-nez v0, :cond_2

    invoke-interface {p1}, Llyiahf/vczjk/mb0;->OooO00o()Z

    move-result p1

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    return-object p1

    :cond_2
    :goto_0
    return-object v1

    :cond_3
    :goto_1
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
