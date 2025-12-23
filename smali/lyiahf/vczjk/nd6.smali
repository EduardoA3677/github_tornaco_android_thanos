.class public final Llyiahf/vczjk/nd6;
.super Llyiahf/vczjk/b23;
.source "SourceFile"


# static fields
.field public static final OooO0Oo:Llyiahf/vczjk/nd6;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/nd6;

    const/4 v1, 0x3

    const/4 v2, 0x1

    const/4 v3, 0x0

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/b23;-><init>(III)V

    sput-object v0, Llyiahf/vczjk/nd6;->OooO0Oo:Llyiahf/vczjk/nd6;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/j11;Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    .locals 6

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/js8;

    const/4 v2, 0x0

    invoke-virtual {p1, v2}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/d7;

    const/4 v4, 0x2

    invoke-virtual {p1, v4}, Llyiahf/vczjk/j11;->OooO0o(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/y13;

    invoke-virtual {v1}, Llyiahf/vczjk/js8;->OooOO0o()Llyiahf/vczjk/os8;

    move-result-object v4

    :try_start_0
    iget-object v5, p1, Llyiahf/vczjk/y13;->OooOo0o:Llyiahf/vczjk/ge6;

    invoke-virtual {v5}, Llyiahf/vczjk/ge6;->Oooooo0()Z

    move-result v5

    if-nez v5, :cond_0

    const-string v5, "FixupList has pending fixup operations that were not realized. Were there mismatched insertNode() and endNodeInsert() calls?"

    invoke-static {v5}, Llyiahf/vczjk/ag1;->OooO0OO(Ljava/lang/String;)V

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/y13;->OooOo0O:Llyiahf/vczjk/ge6;

    invoke-virtual {p1, p2, v4, p4}, Llyiahf/vczjk/ge6;->OooooOo(Llyiahf/vczjk/cx;Llyiahf/vczjk/os8;Llyiahf/vczjk/go7;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v4, v0}, Llyiahf/vczjk/os8;->OooO0o0(Z)V

    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooO0Oo()V

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/js8;->OooO(Llyiahf/vczjk/d7;)I

    move-result p1

    invoke-virtual {p3, v1, p1}, Llyiahf/vczjk/os8;->OooOoO0(Llyiahf/vczjk/js8;I)V

    invoke-virtual {p3}, Llyiahf/vczjk/os8;->OooOO0()V

    return-void

    :catchall_0
    move-exception p1

    invoke-virtual {v4, v2}, Llyiahf/vczjk/os8;->OooO0o0(Z)V

    throw p1
.end method
