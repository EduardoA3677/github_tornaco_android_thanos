.class public final Llyiahf/vczjk/hh9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/lh9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lh9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hh9;->this$0:Llyiahf/vczjk/lh9;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/an;

    iget-object p1, p0, Llyiahf/vczjk/hh9;->this$0:Llyiahf/vczjk/lh9;

    iget-object v0, p1, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    sget-object v8, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    if-eqz v0, :cond_2

    iget-object v2, v0, Llyiahf/vczjk/fh9;->OooO0O0:Llyiahf/vczjk/an;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    iput-object v1, v0, Llyiahf/vczjk/fh9;->OooO0O0:Llyiahf/vczjk/an;

    iget-object v0, v0, Llyiahf/vczjk/fh9;->OooO0Oo:Llyiahf/vczjk/pq5;

    if-eqz v0, :cond_3

    iget-object v2, p1, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v3, p1, Llyiahf/vczjk/lh9;->OooOoo:Llyiahf/vczjk/aa3;

    iget v4, p1, Llyiahf/vczjk/lh9;->OooOooo:I

    iget-boolean v5, p1, Llyiahf/vczjk/lh9;->Oooo000:Z

    iget v6, p1, Llyiahf/vczjk/lh9;->Oooo00O:I

    iget p1, p1, Llyiahf/vczjk/lh9;->Oooo00o:I

    iput-object v1, v0, Llyiahf/vczjk/pq5;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v0, Llyiahf/vczjk/pq5;->OooOO0O:Llyiahf/vczjk/rn9;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/rn9;->OooO0OO(Llyiahf/vczjk/rn9;)Z

    move-result v1

    iput-object v2, v0, Llyiahf/vczjk/pq5;->OooOO0O:Llyiahf/vczjk/rn9;

    const/4 v2, -0x1

    const/4 v7, 0x0

    if-nez v1, :cond_1

    iput-object v7, v0, Llyiahf/vczjk/pq5;->OooOO0o:Llyiahf/vczjk/oq5;

    iput-object v7, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    iput v2, v0, Llyiahf/vczjk/pq5;->OooOOOo:I

    iput v2, v0, Llyiahf/vczjk/pq5;->OooOOOO:I

    :cond_1
    iput-object v3, v0, Llyiahf/vczjk/pq5;->OooO0O0:Llyiahf/vczjk/aa3;

    iput v4, v0, Llyiahf/vczjk/pq5;->OooO0OO:I

    iput-boolean v5, v0, Llyiahf/vczjk/pq5;->OooO0Oo:Z

    iput v6, v0, Llyiahf/vczjk/pq5;->OooO0o0:I

    iput p1, v0, Llyiahf/vczjk/pq5;->OooO0o:I

    iput-object v8, v0, Llyiahf/vczjk/pq5;->OooO0oO:Ljava/util/List;

    iput-object v7, v0, Llyiahf/vczjk/pq5;->OooOO0o:Llyiahf/vczjk/oq5;

    iput-object v7, v0, Llyiahf/vczjk/pq5;->OooOOO:Llyiahf/vczjk/mm9;

    iput v2, v0, Llyiahf/vczjk/pq5;->OooOOOo:I

    iput v2, v0, Llyiahf/vczjk/pq5;->OooOOOO:I

    goto :goto_0

    :cond_2
    new-instance v9, Llyiahf/vczjk/fh9;

    iget-object v0, p1, Llyiahf/vczjk/lh9;->OooOoOO:Llyiahf/vczjk/an;

    invoke-direct {v9, v0, v1}, Llyiahf/vczjk/fh9;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/an;)V

    new-instance v0, Llyiahf/vczjk/pq5;

    iget-object v2, p1, Llyiahf/vczjk/lh9;->OooOoo0:Llyiahf/vczjk/rn9;

    iget-object v3, p1, Llyiahf/vczjk/lh9;->OooOoo:Llyiahf/vczjk/aa3;

    iget v4, p1, Llyiahf/vczjk/lh9;->OooOooo:I

    iget-boolean v5, p1, Llyiahf/vczjk/lh9;->Oooo000:Z

    iget v6, p1, Llyiahf/vczjk/lh9;->Oooo00O:I

    iget v7, p1, Llyiahf/vczjk/lh9;->Oooo00o:I

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/pq5;-><init>(Llyiahf/vczjk/an;Llyiahf/vczjk/rn9;Llyiahf/vczjk/aa3;IZIILjava/util/List;)V

    invoke-virtual {p1}, Llyiahf/vczjk/lh9;->o00000OO()Llyiahf/vczjk/pq5;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/pq5;->OooOO0:Llyiahf/vczjk/f62;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pq5;->OooO0OO(Llyiahf/vczjk/f62;)V

    iput-object v0, v9, Llyiahf/vczjk/fh9;->OooO0Oo:Llyiahf/vczjk/pq5;

    iput-object v9, p1, Llyiahf/vczjk/lh9;->Oooo:Llyiahf/vczjk/fh9;

    :cond_3
    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/hh9;->this$0:Llyiahf/vczjk/lh9;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    invoke-static {p1}, Llyiahf/vczjk/t51;->Oooo00o(Llyiahf/vczjk/go4;)V

    invoke-static {p1}, Llyiahf/vczjk/ye5;->OooOoO0(Llyiahf/vczjk/fg2;)V

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
