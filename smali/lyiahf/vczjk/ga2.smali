.class public final synthetic Llyiahf/vczjk/ga2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/tw8;

.field public final synthetic OooOOO0:Z

.field public final synthetic OooOOOO:Llyiahf/vczjk/ku5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ku5;Llyiahf/vczjk/tw8;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p3, p0, Llyiahf/vczjk/ga2;->OooOOO0:Z

    iput-object p2, p0, Llyiahf/vczjk/ga2;->OooOOO:Llyiahf/vczjk/tw8;

    iput-object p1, p0, Llyiahf/vczjk/ga2;->OooOOOO:Llyiahf/vczjk/ku5;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/ga2;->OooOOOO:Llyiahf/vczjk/ku5;

    iget-boolean v0, p0, Llyiahf/vczjk/ga2;->OooOOO0:Z

    iget-object v1, p0, Llyiahf/vczjk/ga2;->OooOOO:Llyiahf/vczjk/tw8;

    if-eqz v0, :cond_0

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tw8;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tw8;->add(Ljava/lang/Object;)Z

    :cond_0
    sget-object v0, Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;

    if-ne p2, v0, :cond_1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tw8;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tw8;->add(Ljava/lang/Object;)Z

    :cond_1
    sget-object v0, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    if-ne p2, v0, :cond_2

    invoke-virtual {v1, p1}, Llyiahf/vczjk/tw8;->remove(Ljava/lang/Object;)Z

    :cond_2
    return-void
.end method
