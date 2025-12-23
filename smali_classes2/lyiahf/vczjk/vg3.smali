.class public abstract Llyiahf/vczjk/vg3;
.super Llyiahf/vczjk/o00O0;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# direct methods
.method public static OooO0O0(Llyiahf/vczjk/sg3;Llyiahf/vczjk/vg3;ILlyiahf/vczjk/qpa;Ljava/lang/Class;)Llyiahf/vczjk/ug3;
    .locals 6

    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    new-instance v0, Llyiahf/vczjk/ug3;

    new-instance v4, Llyiahf/vczjk/tg3;

    const/4 v1, 0x1

    invoke-direct {v4, p2, p3, v1}, Llyiahf/vczjk/tg3;-><init>(ILlyiahf/vczjk/upa;Z)V

    move-object v1, p0

    move-object v3, p1

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/ug3;-><init>(Llyiahf/vczjk/sg3;Ljava/lang/Object;Llyiahf/vczjk/vg3;Llyiahf/vczjk/tg3;Ljava/lang/Class;)V

    return-object v0
.end method

.method public static OooO0OO(Llyiahf/vczjk/sg3;Ljava/io/Serializable;Llyiahf/vczjk/vg3;ILlyiahf/vczjk/upa;Ljava/lang/Class;)Llyiahf/vczjk/ug3;
    .locals 3

    move v0, p3

    move-object p3, p2

    move-object p2, p1

    move-object p1, p0

    new-instance p0, Llyiahf/vczjk/ug3;

    move-object v1, p4

    new-instance p4, Llyiahf/vczjk/tg3;

    const/4 v2, 0x0

    invoke-direct {p4, v0, v1, v2}, Llyiahf/vczjk/tg3;-><init>(ILlyiahf/vczjk/upa;Z)V

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/ug3;-><init>(Llyiahf/vczjk/sg3;Ljava/lang/Object;Llyiahf/vczjk/vg3;Llyiahf/vczjk/tg3;Ljava/lang/Class;)V

    return-object p0
.end method
