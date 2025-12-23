.class public final Llyiahf/vczjk/hz9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $this_createChildTransitionInternal:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $transition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz9;Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hz9;->$this_createChildTransitionInternal:Llyiahf/vczjk/bz9;

    iput-object p2, p0, Llyiahf/vczjk/hz9;->$transition:Llyiahf/vczjk/bz9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/hz9;->$this_createChildTransitionInternal:Llyiahf/vczjk/bz9;

    iget-object v0, p0, Llyiahf/vczjk/hz9;->$transition:Llyiahf/vczjk/bz9;

    iget-object p1, p1, Llyiahf/vczjk/bz9;->OooOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tw8;->add(Ljava/lang/Object;)Z

    iget-object p1, p0, Llyiahf/vczjk/hz9;->$this_createChildTransitionInternal:Llyiahf/vczjk/bz9;

    iget-object v0, p0, Llyiahf/vczjk/hz9;->$transition:Llyiahf/vczjk/bz9;

    new-instance v1, Llyiahf/vczjk/xb;

    const/16 v2, 0xa

    invoke-direct {v1, v2, p1, v0}, Llyiahf/vczjk/xb;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v1
.end method
