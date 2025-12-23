.class public final Llyiahf/vczjk/ak9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/dp5;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mk9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ak9;->OooO00o:Llyiahf/vczjk/mk9;

    return-void
.end method


# virtual methods
.method public final OooO00o(JLlyiahf/vczjk/md8;)Z
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/ak9;->OooO00o:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOO0O()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-eqz v1, :cond_3

    invoke-virtual {v1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    iget-object v1, v0, Llyiahf/vczjk/mk9;->OooOO0o:Llyiahf/vczjk/w83;

    if-eqz v1, :cond_2

    invoke-static {v1}, Llyiahf/vczjk/w83;->OooO0O0(Llyiahf/vczjk/w83;)V

    :cond_2
    iput-wide p1, v0, Llyiahf/vczjk/mk9;->OooOOOO:J

    const/4 p1, -0x1

    iput p1, v0, Llyiahf/vczjk/mk9;->OooOo00:I

    const/4 p1, 0x1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/mk9;->OooO0oo(Z)V

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v2

    iget-wide v3, v0, Llyiahf/vczjk/mk9;->OooOOOO:J

    const/4 v5, 0x1

    move-object v1, p0

    move-object v6, p3

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/ak9;->OooO0Oo(Llyiahf/vczjk/gl9;JZLlyiahf/vczjk/md8;)V

    return p1

    :cond_3
    :goto_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0O0()V
    .locals 0

    return-void
.end method

.method public final OooO0OO(JLlyiahf/vczjk/md8;)Z
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/ak9;->OooO00o:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOO0O()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/mk9;->OooO0Oo:Llyiahf/vczjk/lx4;

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v1

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO0()Llyiahf/vczjk/gl9;

    move-result-object v4

    const/4 v7, 0x0

    move-object v3, p0

    move-wide v5, p1

    move-object v8, p3

    invoke-virtual/range {v3 .. v8}, Llyiahf/vczjk/ak9;->OooO0Oo(Llyiahf/vczjk/gl9;JZLlyiahf/vczjk/md8;)V

    const/4 p1, 0x1

    return p1

    :cond_2
    :goto_0
    return v2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/gl9;JZLlyiahf/vczjk/md8;)V
    .locals 8

    const/4 v7, 0x0

    iget-object v0, p0, Llyiahf/vczjk/ak9;->OooO00o:Llyiahf/vczjk/mk9;

    const/4 v5, 0x0

    move-object v1, p1

    move-wide v2, p2

    move v4, p4

    move-object v6, p5

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/mk9;->OooO0OO(Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;JZZLlyiahf/vczjk/md8;Z)J

    move-result-wide p1

    invoke-static {p1, p2}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result p1

    if-eqz p1, :cond_0

    sget-object p1, Llyiahf/vczjk/vl3;->OooOOOO:Llyiahf/vczjk/vl3;

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/vl3;->OooOOO:Llyiahf/vczjk/vl3;

    :goto_0
    iget-object p2, p0, Llyiahf/vczjk/ak9;->OooO00o:Llyiahf/vczjk/mk9;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/mk9;->OooOOo0(Llyiahf/vczjk/vl3;)V

    return-void
.end method
