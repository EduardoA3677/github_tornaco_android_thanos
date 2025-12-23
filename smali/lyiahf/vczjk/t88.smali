.class public abstract Llyiahf/vczjk/t88;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const-string v0, "Schedulers"

    invoke-static {v0}, Llyiahf/vczjk/o55;->OooOOOO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/t88;->OooO00o:Ljava/lang/String;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/bra;Llyiahf/vczjk/vp3;Ljava/util/ArrayList;)V
    .locals 2

    invoke-virtual {p2}, Ljava/util/ArrayList;->size()I

    move-result v0

    if-lez v0, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    invoke-virtual {p2}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ara;

    iget-object p2, p2, Llyiahf/vczjk/ara;->OooO00o:Ljava/lang/String;

    invoke-virtual {p0, v0, v1, p2}, Llyiahf/vczjk/bra;->OooO0oo(JLjava/lang/String;)V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/wh1;Landroidx/work/impl/WorkDatabase;Ljava/util/List;)V
    .locals 3

    if-eqz p2, :cond_4

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v0

    if-nez v0, :cond_0

    goto/16 :goto_2

    :cond_0
    invoke-virtual {p1}, Landroidx/work/impl/WorkDatabase;->OooO0oo()Llyiahf/vczjk/bra;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->beginTransaction()V

    :try_start_0
    invoke-virtual {v0}, Llyiahf/vczjk/bra;->OooO0OO()Ljava/util/ArrayList;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/t88;->OooO00o(Llyiahf/vczjk/bra;Llyiahf/vczjk/vp3;Ljava/util/ArrayList;)V

    iget v2, p0, Llyiahf/vczjk/wh1;->OooOO0O:I

    invoke-virtual {v0, v2}, Llyiahf/vczjk/bra;->OooO0O0(I)Ljava/util/ArrayList;

    move-result-object v2

    iget-object p0, p0, Llyiahf/vczjk/wh1;->OooO0Oo:Llyiahf/vczjk/vp3;

    invoke-static {v0, p0, v2}, Llyiahf/vczjk/t88;->OooO00o(Llyiahf/vczjk/bra;Llyiahf/vczjk/vp3;Ljava/util/ArrayList;)V

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v0}, Llyiahf/vczjk/bra;->OooO00o()Ljava/util/ArrayList;

    move-result-object p0

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->setTransactionSuccessful()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->endTransaction()V

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result p1

    if-lez p1, :cond_2

    invoke-virtual {v2}, Ljava/util/ArrayList;->size()I

    move-result p1

    new-array p1, p1, [Llyiahf/vczjk/ara;

    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    check-cast p1, [Llyiahf/vczjk/ara;

    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/j88;

    invoke-interface {v1}, Llyiahf/vczjk/j88;->OooO0O0()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1, p1}, Llyiahf/vczjk/j88;->OooO0OO([Llyiahf/vczjk/ara;)V

    goto :goto_0

    :cond_2
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result p1

    if-lez p1, :cond_4

    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result p1

    new-array p1, p1, [Llyiahf/vczjk/ara;

    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p0

    check-cast p0, [Llyiahf/vczjk/ara;

    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    if-eqz p2, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/j88;

    invoke-interface {p2}, Llyiahf/vczjk/j88;->OooO0O0()Z

    move-result v0

    if-nez v0, :cond_3

    invoke-interface {p2, p0}, Llyiahf/vczjk/j88;->OooO0OO([Llyiahf/vczjk/ara;)V

    goto :goto_1

    :catchall_0
    move-exception p0

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->endTransaction()V

    throw p0

    :cond_4
    :goto_2
    return-void
.end method
