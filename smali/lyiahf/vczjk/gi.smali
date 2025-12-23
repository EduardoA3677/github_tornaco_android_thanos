.class public final Llyiahf/vczjk/gi;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/dm;

.field public final OooO00o:Llyiahf/vczjk/m1a;

.field public final OooO0O0:Ljava/lang/Object;

.field public final OooO0OO:Llyiahf/vczjk/xl;

.field public final OooO0Oo:Llyiahf/vczjk/qs5;

.field public final OooO0o:Llyiahf/vczjk/it5;

.field public final OooO0o0:Llyiahf/vczjk/qs5;

.field public final OooO0oO:Llyiahf/vczjk/wz8;

.field public final OooO0oo:Llyiahf/vczjk/dm;

.field public OooOO0:Llyiahf/vczjk/dm;

.field public OooOO0O:Llyiahf/vczjk/dm;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/String;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    iput-object p3, p0, Llyiahf/vczjk/gi;->OooO0O0:Ljava/lang/Object;

    new-instance p4, Llyiahf/vczjk/xl;

    const/16 v0, 0x3c

    const/4 v1, 0x0

    invoke-direct {p4, p2, p1, v1, v0}, Llyiahf/vczjk/xl;-><init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;I)V

    iput-object p4, p0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    new-instance p1, Llyiahf/vczjk/it5;

    invoke-direct {p1}, Llyiahf/vczjk/it5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gi;->OooO0o:Llyiahf/vczjk/it5;

    new-instance p1, Llyiahf/vczjk/wz8;

    invoke-direct {p1, p3}, Llyiahf/vczjk/wz8;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/gi;->OooO0oO:Llyiahf/vczjk/wz8;

    iget-object p1, p4, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    instance-of p2, p1, Llyiahf/vczjk/zl;

    if-eqz p2, :cond_0

    sget-object p3, Llyiahf/vczjk/mc4;->OooOOo0:Llyiahf/vczjk/zl;

    goto :goto_0

    :cond_0
    instance-of p3, p1, Llyiahf/vczjk/am;

    if-eqz p3, :cond_1

    sget-object p3, Llyiahf/vczjk/mc4;->OooOOo:Llyiahf/vczjk/am;

    goto :goto_0

    :cond_1
    instance-of p3, p1, Llyiahf/vczjk/bm;

    if-eqz p3, :cond_2

    sget-object p3, Llyiahf/vczjk/mc4;->OooOOoo:Llyiahf/vczjk/bm;

    goto :goto_0

    :cond_2
    sget-object p3, Llyiahf/vczjk/mc4;->OooOo00:Llyiahf/vczjk/cm;

    :goto_0
    iput-object p3, p0, Llyiahf/vczjk/gi;->OooO0oo:Llyiahf/vczjk/dm;

    if-eqz p2, :cond_3

    sget-object p1, Llyiahf/vczjk/mc4;->OooOOO0:Llyiahf/vczjk/zl;

    goto :goto_1

    :cond_3
    instance-of p2, p1, Llyiahf/vczjk/am;

    if-eqz p2, :cond_4

    sget-object p1, Llyiahf/vczjk/mc4;->OooOOO:Llyiahf/vczjk/am;

    goto :goto_1

    :cond_4
    instance-of p1, p1, Llyiahf/vczjk/bm;

    if-eqz p1, :cond_5

    sget-object p1, Llyiahf/vczjk/mc4;->OooOOOO:Llyiahf/vczjk/bm;

    goto :goto_1

    :cond_5
    sget-object p1, Llyiahf/vczjk/mc4;->OooOOOo:Llyiahf/vczjk/cm;

    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/gi;->OooO:Llyiahf/vczjk/dm;

    iput-object p3, p0, Llyiahf/vczjk/gi;->OooOO0:Llyiahf/vczjk/dm;

    iput-object p1, p0, Llyiahf/vczjk/gi;->OooOO0O:Llyiahf/vczjk/dm;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V
    .locals 0

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    const/4 p3, 0x0

    :cond_0
    const-string p4, "Animatable"

    invoke-direct {p0, p1, p2, p3, p4}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/gi;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v1, v0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    invoke-virtual {v1}, Llyiahf/vczjk/dm;->OooO0Oo()V

    const-wide/high16 v1, -0x8000000000000000L

    iput-wide v1, v0, Llyiahf/vczjk/xl;->OooOOOo:J

    iget-object p0, p0, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast p0, Llyiahf/vczjk/fw8;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;
    .locals 10

    and-int/lit8 v0, p5, 0x2

    if-eqz v0, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/gi;->OooO0oO:Llyiahf/vczjk/wz8;

    :cond_0
    move-object v1, p2

    iget-object p2, p0, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    check-cast p2, Llyiahf/vczjk/n1a;

    iget-object p2, p2, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v0, v0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    invoke-interface {p2, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_1

    const/4 p3, 0x0

    :cond_1
    move-object v8, p3

    invoke-virtual {p0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v3

    new-instance v0, Llyiahf/vczjk/fg9;

    iget-object v2, p0, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    move-object p3, v2

    check-cast p3, Llyiahf/vczjk/n1a;

    iget-object p3, p3, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {p3, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    move-object v5, p3

    check-cast v5, Llyiahf/vczjk/dm;

    move-object v4, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/fg9;-><init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V

    iget-object p1, p0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-wide v6, p1, Llyiahf/vczjk/xl;->OooOOOo:J

    new-instance v2, Llyiahf/vczjk/bi;

    const/4 v9, 0x0

    move-object v3, p0

    move-object v4, p2

    move-object v5, v0

    invoke-direct/range {v2 .. v9}, Llyiahf/vczjk/bi;-><init>(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    iget-object p0, v3, Llyiahf/vczjk/gi;->OooO0o:Llyiahf/vczjk/it5;

    invoke-static {p0, v2, p4}, Llyiahf/vczjk/it5;->OooO00o(Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final OooO0OO(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/gi;->OooOO0:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/gi;->OooO0oo:Llyiahf/vczjk/dm;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/gi;->OooOO0O:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/gi;->OooO:Llyiahf/vczjk/dm;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v1, v0, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/dm;

    invoke-virtual {v1}, Llyiahf/vczjk/dm;->OooO0O0()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v3, v2, :cond_3

    invoke-virtual {v1, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v5

    iget-object v6, p0, Llyiahf/vczjk/gi;->OooOO0:Llyiahf/vczjk/dm;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v6

    cmpg-float v5, v5, v6

    if-ltz v5, :cond_1

    invoke-virtual {v1, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v5

    iget-object v6, p0, Llyiahf/vczjk/gi;->OooOO0O:Llyiahf/vczjk/dm;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v6

    cmpl-float v5, v5, v6

    if-lez v5, :cond_2

    :cond_1
    invoke-virtual {v1, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v4

    iget-object v5, p0, Llyiahf/vczjk/gi;->OooOO0:Llyiahf/vczjk/dm;

    invoke-virtual {v5, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v5

    iget-object v6, p0, Llyiahf/vczjk/gi;->OooOO0O:Llyiahf/vczjk/dm;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v6

    invoke-static {v4, v5, v6}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v4

    invoke-virtual {v1, v4, v3}, Llyiahf/vczjk/dm;->OooO0o0(FI)V

    const/4 v4, 0x1

    :cond_2
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_3
    if-eqz v4, :cond_4

    iget-object p1, v0, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {p1, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    :cond_4
    :goto_1
    return-object p1
.end method

.method public final OooO0Oo()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v0, v0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/di;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/di;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/yo1;)V

    iget-object v1, p0, Llyiahf/vczjk/gi;->OooO0o:Llyiahf/vczjk/it5;

    invoke-static {v1, v0, p1}, Llyiahf/vczjk/it5;->OooO00o(Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ci;

    const/4 v1, 0x0

    invoke-direct {v0, p0, p1, v1}, Llyiahf/vczjk/ci;-><init>(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    iget-object p1, p0, Llyiahf/vczjk/gi;->OooO0o:Llyiahf/vczjk/it5;

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/it5;->OooO00o(Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0oO(Ljava/lang/Float;Ljava/lang/Float;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/n1a;

    iget-object v1, v1, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm;

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/gi;->OooO0oo:Llyiahf/vczjk/dm;

    :cond_0
    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v0, v0, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/dm;

    if-nez p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/gi;->OooO:Llyiahf/vczjk/dm;

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/dm;->OooO0O0()I

    move-result v0

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_3

    invoke-virtual {p1, v1}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v2

    invoke-virtual {p2, v1}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v3

    cmpg-float v2, v2, v3

    if-gtz v2, :cond_2

    goto :goto_1

    :cond_2
    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Lower bound must be no greater than upper bound on *all* dimensions. The provided lower bound: "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " is greater than upper bound "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, " on index "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/w07;->OooO0O0(Ljava/lang/String;)V

    :goto_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_3
    iput-object p1, p0, Llyiahf/vczjk/gi;->OooOO0:Llyiahf/vczjk/dm;

    iput-object p2, p0, Llyiahf/vczjk/gi;->OooOO0O:Llyiahf/vczjk/dm;

    iget-object p1, p0, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-nez p1, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/gi;->OooO0OO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_4

    iget-object p2, p0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object p2, p2, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast p2, Llyiahf/vczjk/fw8;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_4
    return-void
.end method
