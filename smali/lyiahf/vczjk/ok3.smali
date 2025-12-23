.class public final Llyiahf/vczjk/ok3;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:Z

.field public final OooO00o:Llyiahf/vczjk/es2;

.field public final OooO0O0:I

.field public final OooO0OO:Llyiahf/vczjk/kx2;

.field public final OooO0Oo:Ljava/util/HashMap;

.field public final OooO0o:Ljava/util/ArrayList;

.field public final OooO0o0:Ljava/util/ArrayList;

.field public final OooO0oO:I

.field public final OooO0oo:I

.field public OooOO0:Llyiahf/vczjk/bc3;

.field public final OooOO0O:Z

.field public final OooOO0o:Llyiahf/vczjk/ts9;

.field public final OooOOO:Ljava/util/ArrayDeque;

.field public final OooOOO0:Llyiahf/vczjk/us9;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/es2;->OooOOOO:Llyiahf/vczjk/es2;

    iput-object v0, p0, Llyiahf/vczjk/ok3;->OooO00o:Llyiahf/vczjk/es2;

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/ok3;->OooO0O0:I

    sget-object v1, Llyiahf/vczjk/rx2;->OooOOO0:Llyiahf/vczjk/kx2;

    iput-object v1, p0, Llyiahf/vczjk/ok3;->OooO0OO:Llyiahf/vczjk/kx2;

    new-instance v1, Ljava/util/HashMap;

    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/ok3;->OooO0Oo:Ljava/util/HashMap;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/ok3;->OooO0o0:Ljava/util/ArrayList;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/ok3;->OooO0o:Ljava/util/ArrayList;

    sget-object v1, Llyiahf/vczjk/nk3;->OooOO0o:Llyiahf/vczjk/bc3;

    const/4 v1, 0x2

    iput v1, p0, Llyiahf/vczjk/ok3;->OooO0oO:I

    iput v1, p0, Llyiahf/vczjk/ok3;->OooO0oo:I

    iput-boolean v0, p0, Llyiahf/vczjk/ok3;->OooO:Z

    sget-object v1, Llyiahf/vczjk/nk3;->OooOO0o:Llyiahf/vczjk/bc3;

    iput-object v1, p0, Llyiahf/vczjk/ok3;->OooOO0:Llyiahf/vczjk/bc3;

    iput-boolean v0, p0, Llyiahf/vczjk/ok3;->OooOO0O:Z

    sget-object v0, Llyiahf/vczjk/nk3;->OooOOO:Llyiahf/vczjk/ts9;

    iput-object v0, p0, Llyiahf/vczjk/ok3;->OooOO0o:Llyiahf/vczjk/ts9;

    sget-object v0, Llyiahf/vczjk/nk3;->OooOOOO:Llyiahf/vczjk/us9;

    iput-object v0, p0, Llyiahf/vczjk/ok3;->OooOOO0:Llyiahf/vczjk/us9;

    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ok3;->OooOOO:Ljava/util/ArrayDeque;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/nk3;
    .locals 15

    const/4 v0, 0x0

    new-instance v11, Ljava/util/ArrayList;

    iget-object v1, p0, Llyiahf/vczjk/ok3;->OooO0o0:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/ok3;->OooO0o:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result v4

    add-int/2addr v4, v2

    add-int/lit8 v4, v4, 0x3

    invoke-direct {v11, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v11, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-static {v11}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-static {v2}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    invoke-virtual {v11, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    sget-boolean v2, Llyiahf/vczjk/g09;->OooO00o:Z

    sget-object v4, Llyiahf/vczjk/q12;->OooO0O0:Llyiahf/vczjk/p12;

    iget v5, p0, Llyiahf/vczjk/ok3;->OooO0oO:I

    iget v6, p0, Llyiahf/vczjk/ok3;->OooO0oo:I

    const/4 v7, 0x2

    if-ne v5, v7, :cond_0

    if-eq v6, v7, :cond_2

    :cond_0
    new-instance v7, Llyiahf/vczjk/r12;

    invoke-direct {v7, v4, v5, v6}, Llyiahf/vczjk/r12;-><init>(Llyiahf/vczjk/q12;II)V

    sget-object v4, Llyiahf/vczjk/x2a;->OooO00o:Llyiahf/vczjk/n2a;

    new-instance v4, Llyiahf/vczjk/n2a;

    const-class v8, Ljava/util/Date;

    invoke-direct {v4, v8, v7, v0}, Llyiahf/vczjk/n2a;-><init>(Ljava/lang/Object;Llyiahf/vczjk/r1a;I)V

    if-eqz v2, :cond_1

    sget-object v7, Llyiahf/vczjk/g09;->OooO0OO:Llyiahf/vczjk/f09;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v8, Llyiahf/vczjk/r12;

    invoke-direct {v8, v7, v5, v6}, Llyiahf/vczjk/r12;-><init>(Llyiahf/vczjk/q12;II)V

    new-instance v9, Llyiahf/vczjk/n2a;

    iget-object v7, v7, Llyiahf/vczjk/q12;->OooO00o:Ljava/lang/Class;

    invoke-direct {v9, v7, v8, v0}, Llyiahf/vczjk/n2a;-><init>(Ljava/lang/Object;Llyiahf/vczjk/r1a;I)V

    sget-object v7, Llyiahf/vczjk/g09;->OooO0O0:Llyiahf/vczjk/f09;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v8, Llyiahf/vczjk/r12;

    invoke-direct {v8, v7, v5, v6}, Llyiahf/vczjk/r12;-><init>(Llyiahf/vczjk/q12;II)V

    new-instance v5, Llyiahf/vczjk/n2a;

    iget-object v6, v7, Llyiahf/vczjk/q12;->OooO00o:Ljava/lang/Class;

    invoke-direct {v5, v6, v8, v0}, Llyiahf/vczjk/n2a;-><init>(Ljava/lang/Object;Llyiahf/vczjk/r1a;I)V

    goto :goto_0

    :cond_1
    const/4 v9, 0x0

    move-object v5, v9

    :goto_0
    invoke-virtual {v11, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    if-eqz v2, :cond_2

    invoke-virtual {v11, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v11, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :cond_2
    move-object v0, v1

    new-instance v1, Llyiahf/vczjk/nk3;

    move-object v2, v3

    iget-object v3, p0, Llyiahf/vczjk/ok3;->OooO0OO:Llyiahf/vczjk/kx2;

    new-instance v4, Ljava/util/HashMap;

    iget-object v5, p0, Llyiahf/vczjk/ok3;->OooO0Oo:Ljava/util/HashMap;

    invoke-direct {v4, v5}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    iget-boolean v5, p0, Llyiahf/vczjk/ok3;->OooO:Z

    iget-object v6, p0, Llyiahf/vczjk/ok3;->OooOO0:Llyiahf/vczjk/bc3;

    iget v8, p0, Llyiahf/vczjk/ok3;->OooO0O0:I

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    new-instance v10, Ljava/util/ArrayList;

    invoke-direct {v10, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iget-object v12, p0, Llyiahf/vczjk/ok3;->OooOO0o:Llyiahf/vczjk/ts9;

    iget-object v13, p0, Llyiahf/vczjk/ok3;->OooOOO0:Llyiahf/vczjk/us9;

    new-instance v14, Ljava/util/ArrayList;

    iget-object v0, p0, Llyiahf/vczjk/ok3;->OooOOO:Ljava/util/ArrayDeque;

    invoke-direct {v14, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iget-object v2, p0, Llyiahf/vczjk/ok3;->OooO00o:Llyiahf/vczjk/es2;

    iget-boolean v7, p0, Llyiahf/vczjk/ok3;->OooOO0O:Z

    invoke-direct/range {v1 .. v14}, Llyiahf/vczjk/nk3;-><init>(Llyiahf/vczjk/es2;Llyiahf/vczjk/rx2;Ljava/util/Map;ZLlyiahf/vczjk/bc3;ZILjava/util/List;Ljava/util/List;Ljava/util/List;Llyiahf/vczjk/xs9;Llyiahf/vczjk/xs9;Ljava/util/List;)V

    return-object v1
.end method
