.class public final Llyiahf/vczjk/aq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $autofillHighlightColor:J

.field final synthetic $state:Llyiahf/vczjk/lx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aq1;->$state:Llyiahf/vczjk/lx4;

    iput-wide p2, p0, Llyiahf/vczjk/aq1;->$autofillHighlightColor:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/hg2;

    iget-object p1, p0, Llyiahf/vczjk/aq1;->$state:Llyiahf/vczjk/lx4;

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOOoo:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/aq1;->$state:Llyiahf/vczjk/lx4;

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOo00:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_1

    :cond_0
    iget-wide v1, p0, Llyiahf/vczjk/aq1;->$autofillHighlightColor:J

    const/4 v8, 0x0

    const/16 v10, 0x7e

    const-wide/16 v3, 0x0

    const-wide/16 v5, 0x0

    const/4 v7, 0x0

    const/4 v9, 0x0

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
